use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
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
    sync::Arc,
};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::info;

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
    };

    // Criar diretório de scripts se não existir
    fs::create_dir_all(&app_state.scripts_dir)?;

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
    // Implementar upload de arquivo aqui
) -> impl IntoResponse {
    // Verificar autenticação
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, "Não autorizado").into_response();
    }

    // TODO: Implementar upload de arquivo
    (StatusCode::NOT_IMPLEMENTED, "Upload não implementado ainda").into_response()
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

    // TODO: Implementar assinatura GPG
    (StatusCode::NOT_IMPLEMENTED, "Funcionalidade de assinatura em desenvolvimento").into_response()
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
