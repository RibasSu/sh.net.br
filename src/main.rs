use anyhow::Result;
use axum::{
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Form, Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    process::Command,
    sync::Arc,
};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{info, error};

mod auth;
mod cert;
mod templates;

use auth::{AuthState, LoginForm, SessionManager};
use cert::generate_self_signed_cert;

#[derive(Clone)]
pub struct AppState {
    pub auth: AuthState,
    pub sessions: Arc<RwLock<SessionManager>>,
    pub scripts_dir: PathBuf,
    pub gpg_home: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct ScriptInfo {
    pub name: String,
    pub size: u64,
    pub hash: String,
    pub signed: bool,
    pub signature: Option<String>,
}

#[derive(Deserialize)]
pub struct ScriptQuery {
    hash: Option<String>,
    verify: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Configurar logging
    tracing_subscriber::fmt::init();

    // Gerar certificado TLS autoassinado
    let cert_path = "certs/cert.pem";
    let key_path = "certs/key.pem";
    
    info!("Gerando novo certificado TLS autoassinado...");
    generate_self_signed_cert(cert_path, key_path)?;

    // Configurar TLS
    let config = RustlsConfig::from_pem_file(cert_path, key_path).await?;

    // Inicializar estado da aplicação
    let app_state = AppState {
        auth: AuthState::new(),
        sessions: Arc::new(RwLock::new(SessionManager::new())),
        scripts_dir: PathBuf::from("scripts"),
        gpg_home: PathBuf::from("gpg_keys"),
    };

    // Criar diretórios necessários
    fs::create_dir_all(&app_state.scripts_dir)?;
    fs::create_dir_all(&app_state.gpg_home)?;

    // Limpar diretório GPG se houver problemas
    cleanup_gpg_if_needed(&app_state.gpg_home).await.ok();

    // Criar aplicação
    let app = create_app(app_state);

    // Iniciar servidor HTTPS
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    info!("Servidor iniciando em https://{}", addr);
    
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

fn create_app(state: AppState) -> Router {
    Router::new()
        // Rotas públicas
        .route("/", get(index))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        
        // Rotas para servir scripts
        .route("/:script", get(serve_script))
        .route("/scripts/:script", get(serve_script))
        
        // Rotas administrativas (requerem autenticação)
        .route("/admin", get(admin_page))
        .route("/admin/upload", post(upload_script))
        .route("/admin/sign/:script", post(sign_script))
        .route("/admin/scripts", get(list_scripts))
        
        // API
        .route("/api/script/:script/info", get(script_info))
        .route("/api/scripts", get(api_list_scripts))
        
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn index() -> impl IntoResponse {
    Html(templates::INDEX_HTML)
}

async fn login_page() -> impl IntoResponse {
    Html(templates::LOGIN_HTML)
}

async fn login(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    match state.auth.verify_credentials(&form.username, &form.password) {
        Ok(true) => {
            let token = state.auth.create_token(&form.username).unwrap();
            let mut sessions = state.sessions.write().await;
            sessions.create_session(form.username.clone(), token.clone());
            
            let mut headers = HeaderMap::new();
            headers.insert(
                header::SET_COOKIE,
                format!("session={}; HttpOnly; Secure; SameSite=Strict; Max-Age=3600", token)
                    .parse()
                    .unwrap(),
            );
            (StatusCode::SEE_OTHER, headers, [("location", "/admin")])
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            HeaderMap::new(),
            [("location", "/login?error=1")],
        ),
    }
}

async fn logout(State(_state): State<AppState>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        "session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
            .parse()
            .unwrap(),
    );
    (StatusCode::SEE_OTHER, headers, [("location", "/")])
}

async fn serve_script(
    Path(script_name): Path<String>,
    Query(query): Query<ScriptQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Sanitizar nome do arquivo
    let script_name = if !script_name.ends_with(".sh") {
        format!("{}.sh", script_name)
    } else {
        script_name
    };

    let script_path = state.scripts_dir.join(&script_name);
    
    // Verificar se o arquivo existe
    if !script_path.exists() {
        return (StatusCode::NOT_FOUND, "Script não encontrado").into_response();
    }

    // Ler arquivo
    let content = match fs::read(&script_path) {
        Ok(content) => content,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Erro ao ler script").into_response(),
    };

    // Calcular hash
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hex::encode(hasher.finalize());

    // Verificar hash se fornecido
    if let Some(expected_hash) = query.hash {
        if hash != expected_hash {
            return (StatusCode::BAD_REQUEST, "Hash não confere").into_response();
        }
    }

    // Verificar assinatura se solicitado
    if query.verify.unwrap_or(false) {
        let sig_path = script_path.with_extension("sh.sig");
        if sig_path.exists() {
            // TODO: Implementar verificação GPG
            info!("Arquivo de assinatura encontrado para {}", script_name);
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    headers.insert("X-Content-Hash", hash.parse().unwrap());
    
    (StatusCode::OK, headers, content).into_response()
}

async fn admin_page(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    // Verificar autenticação
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::SEE_OTHER, [("location", "/login")]).into_response();
    }

    Html(templates::ADMIN_HTML).into_response()
}

async fn list_scripts(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Verificar autenticação
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, "Não autorizado").into_response();
    }

    let scripts = get_script_list(&state).await;
    Html(templates::render_script_list(&scripts)).into_response()
}

async fn script_info(
    Path(script_name): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let script_name = if !script_name.ends_with(".sh") {
        format!("{}.sh", script_name)
    } else {
        script_name
    };

    let info = get_script_info(&state, &script_name).await;
    match info {
        Some(info) => Json(info).into_response(),
        None => (StatusCode::NOT_FOUND, "Script não encontrado").into_response(),
    }
}

async fn api_list_scripts(State(state): State<AppState>) -> impl IntoResponse {
    let scripts = get_script_list(&state).await;
    Json(scripts)
}

async fn upload_script(
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // Verificar autenticação
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, "Não autorizado").into_response();
    }

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap_or("").to_string();
        let filename = field.file_name().unwrap_or("").to_string();
        
        if name == "script" && filename.ends_with(".sh") {
            let data = field.bytes().await.unwrap();
            
            // Validar nome do arquivo (sanitizar)
            let safe_filename = filename
                .replace('/', "")
                .replace('\\', "")
                .replace("..", "");
            if safe_filename.is_empty() || !safe_filename.ends_with(".sh") {
                return (StatusCode::BAD_REQUEST, "Nome de arquivo inválido").into_response();
            }
            
            let script_path = state.scripts_dir.join(&safe_filename);
            
            // Verificar se não está sobrescrevendo arquivo existente (opcional)
            if script_path.exists() {
                return (StatusCode::CONFLICT, "Arquivo já existe").into_response();
            }
            
            match fs::write(&script_path, data) {
                Ok(_) => {
                    info!("Script {} carregado com sucesso", safe_filename);
                    return (
                        StatusCode::SEE_OTHER,
                        [("location", "/admin")],
                        format!("Script {} carregado com sucesso", safe_filename)
                    ).into_response();
                }
                Err(e) => {
                    error!("Erro ao salvar script: {}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Erro ao salvar arquivo").into_response();
                }
            }
        }
    }

    (StatusCode::BAD_REQUEST, "Nenhum arquivo válido encontrado").into_response()
}

async fn sign_script(
    headers: HeaderMap,
    Path(script_name): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Verificar autenticação
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, "Não autorizado").into_response();
    }

    let script_path = state.scripts_dir.join(&script_name);
    if !script_path.exists() {
        return (StatusCode::NOT_FOUND, "Script não encontrado").into_response();
    }

    // Implementar assinatura usando GPG do sistema
    match sign_file_with_gpg(&script_path, &state.gpg_home).await {
        Ok(_) => {
            info!("Script {} assinado com sucesso", script_name);
            (StatusCode::OK, "Script assinado com sucesso").into_response()
        }
        Err(e) => {
            error!("Erro ao assinar script {}: {}", script_name, e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Erro ao assinar: {}", e)).into_response()
        }
    }
}

async fn is_authenticated(headers: &HeaderMap, state: &AppState) -> bool {
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if cookie.starts_with("session=") {
                    let token = &cookie[8..];
                    let mut sessions = state.sessions.write().await;
                    return sessions.is_valid_session(token);
                }
            }
        }
    }
    false
}

async fn get_script_list(state: &AppState) -> Vec<ScriptInfo> {
    let mut scripts = Vec::new();
    
    if let Ok(entries) = fs::read_dir(&state.scripts_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".sh") {
                    if let Some(info) = get_script_info(state, name).await {
                        scripts.push(info);
                    }
                }
            }
        }
    }
    
    scripts
}

async fn get_script_info(state: &AppState, script_name: &str) -> Option<ScriptInfo> {
    let script_path = state.scripts_dir.join(script_name);
    
    if !script_path.exists() {
        return None;
    }

    let metadata = fs::metadata(&script_path).ok()?;
    let content = fs::read(&script_path).ok()?;
    
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hex::encode(hasher.finalize());

    let sig_path = script_path.with_extension("sh.sig");
    let signed = sig_path.exists();
    let signature = if signed {
        fs::read_to_string(&sig_path).ok()
    } else {
        None
    };

    Some(ScriptInfo {
        name: script_name.to_string(),
        size: metadata.len(),
        hash,
        signed,
        signature,
    })
}

// Função para inicializar GPG se necessário
async fn initialize_gpg(gpg_home: &PathBuf) -> Result<(), String> {
    // Criar diretório GPG se não existir
    if let Err(e) = fs::create_dir_all(gpg_home) {
        return Err(format!("Erro ao criar diretório GPG: {}", e));
    }

    // Verificar se já existem chaves utilizáveis
    let email = "sh@sh.net.br";
    
    // Primeiro verificar se a chave específica existe
    let output = Command::new("gpg")
        .args(&[
            "--list-secret-keys",
            "--with-colons",
            email,
        ])
        .output()
        .map_err(|e| format!("Erro ao verificar chaves existentes: {}", e))?;

    if output.status.success() && !output.stdout.is_empty() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Verificar se realmente encontrou uma chave secreta para o email
        if stdout.lines().any(|line| line.starts_with("sec:")) {
            info!("Chave GPG existente encontrada para {}", email);
            return Ok(());
        }
    }

    // Verificar se os arquivos de chave exportados existem
    let public_key_file = gpg_home.join("public.gpg");
    let private_key_file = gpg_home.join("private.gpg");
    
    if public_key_file.exists() && private_key_file.exists() {
        info!("Arquivos de chave GPG encontrados, importando...");
        
        // Tentar importar a chave privada
        let import_output = Command::new("gpg")
            .args(&[
                "--import",
                &private_key_file.to_string_lossy(),
            ])
            .output()
            .map_err(|e| format!("Erro ao importar chave privada: {}", e))?;

        if import_output.status.success() {
            info!("Chave GPG importada com sucesso");
            return Ok(());
        }
    }

    // Só gerar nova chave se realmente não existir nenhuma
    info!("Nenhuma chave GPG encontrada, gerando nova usando script setup.sh...");
    
    let setup_script = gpg_home.join("setup.sh");
    
    // Verificar se o script existe
    if !setup_script.exists() {
        return Err(format!("Script setup.sh não encontrado em: {}", setup_script.display()));
    }

    // Executar o script setup.sh com caminho absoluto
    let output = Command::new("/bin/bash")
        .arg(&setup_script)
        .output()
        .map_err(|e| format!("Erro ao executar setup.sh: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Falha ao executar setup.sh: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    info!("Chave GPG gerada com sucesso usando setup.sh");
    info!("Saída: {}", String::from_utf8_lossy(&output.stdout));
    
    Ok(())
}

// Função para assinar arquivo com GPG
async fn sign_file_with_gpg(file_path: &PathBuf, gpg_home: &PathBuf) -> Result<(), String> {
    // Inicializar GPG se necessário
    initialize_gpg(gpg_home).await?;

    let sig_path = file_path.with_extension("sh.sig");

    // Usar o email definido no script setup.sh para encontrar a chave
    let email = "sh@sh.net.br";

    // Assinar o arquivo usando o email como identificador da chave
    let output = Command::new("gpg")
        .args(&[
            "--armor",
            "--detach-sign",
            "--yes", // Sobrescrever se já existir
            "--default-key",
            email,
            "--output",
            &sig_path.to_string_lossy(),
            &file_path.to_string_lossy(),
        ])
        .output()
        .map_err(|e| format!("Erro ao executar assinatura: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Falha ao assinar arquivo: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    info!("Arquivo {} assinado com sucesso", file_path.display());
    Ok(())
}

// Função para limpar diretório GPG em caso de problemas
async fn cleanup_gpg_if_needed(gpg_home: &PathBuf) -> Result<(), String> {
    // Verificar se o diretório GPG tem problemas
    let test_output = Command::new("gpg")
        .args(&[
            "--homedir",
            &gpg_home.to_string_lossy(),
            "--list-keys",
        ])
        .output();

    if let Ok(output) = test_output {
        if output.status.success() {
            return Ok(()); // GPG está funcionando
        }
        
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("permissões inseguras") || stderr.contains("unsafe permissions") {
            info!("Limpando diretório GPG devido a permissões inseguras...");
            
            // Remover e recriar diretório
            if gpg_home.exists() {
                fs::remove_dir_all(gpg_home).ok();
            }
            fs::create_dir_all(gpg_home).ok();
            
            // Definir permissões corretas
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = fs::metadata(gpg_home) {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o700);
                    fs::set_permissions(gpg_home, perms).ok();
                }
            }
        }
    }

    Ok(())
}
