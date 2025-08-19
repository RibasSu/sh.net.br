use crate::ScriptInfo;

pub const INDEX_HTML: &str = r#"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SH.NET.BR - Servidor de Scripts Bash</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
            line-height: 1.6;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
        }
        .feature {
            background: #ecf0f1;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }
        .admin-link {
            display: block;
            text-align: center;
            margin-top: 30px;
            padding: 10px 20px;
            background: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        .admin-link:hover {
            background: #2980b9;
        }
        .example {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            margin: 15px 0;
        }
        .security-note {
            background: #e74c3c;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SH.NET.BR</h1>
        <h2>Servidor Seguro de Scripts Bash</h2>
        
        <div class="feature">
            <h3>📁 Acesso a Scripts</h3>
            <p>Acesse seus scripts bash de forma segura através de URLs simples:</p>
            <div class="example">
                curl https://sh.net.br/meu-script.sh<br>
                curl https://meu-script.sh.net.br<br>
                curl https://sh.net.br/scripts/meu-script.sh
            </div>
        </div>

        <div class="feature">
            <h3>🔐 Verificação de Integridade</h3>
            <p>Todos os scripts incluem verificação de hash SHA-256:</p>
            <div class="example">
                curl https://sh.net.br/meu-script.sh?hash=abc123...<br>
                curl -I https://sh.net.br/meu-script.sh | grep X-Content-Hash
            </div>
        </div>

        <div class="feature">
            <h3>✍️ Assinatura GPG</h3>
            <p>Scripts podem ser assinados digitalmente com GPG:</p>
            <div class="example">
                curl https://sh.net.br/meu-script.sh?verify=true<br>
                curl https://sh.net.br/meu-script.sh.sig
            </div>
        </div>

        <div class="feature">
            <h3>🌐 Múltiplos Formatos de URL</h3>
            <p>Suporte flexível para diferentes padrões de URL:</p>
            <ul>
                <li><code>sh.net.br/script.sh</code></li>
                <li><code>script.sh.net.br</code></li>
                <li><code>sh.net.br/scripts/script.sh</code></li>
            </ul>
        </div>

        <div class="security-note">
            <h3>🔒 Segurança</h3>
            <p>Este servidor utiliza HTTPS obrigatório com certificados TLS autoassinados renovados automaticamente. 
            Funciona perfeitamente atrás de um proxy CloudFlare para validação de certificados.</p>
        </div>

        <a href="/admin" class="admin-link">🔧 Painel Administrativo</a>
    </div>
</body>
</html>
"#;

pub const LOGIN_HTML: &str = r#"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - SH.NET.BR</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            text-align: center;
            color: #2c3e50;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
            box-sizing: border-box;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: #3498db;
        }
        .submit-btn {
            width: 100%;
            padding: 12px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .submit-btn:hover {
            background: #2980b9;
        }
        .error {
            color: #e74c3c;
            text-align: center;
            margin-top: 15px;
        }
        .back-link {
            text-align: center;
            margin-top: 20px;
        }
        .back-link a {
            color: #3498db;
            text-decoration: none;
        }
        .back-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔐 Login</h1>
        <form method="post" action="/login">
            <div class="form-group">
                <label for="username">Usuário:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Senha:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="submit-btn">Entrar</button>
        </form>
        
        <script>
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.get('error') === '1') {
                const errorDiv = document.createElement('div');
                errorDiv.className = 'error';
                errorDiv.textContent = 'Usuário ou senha inválidos';
                document.querySelector('form').appendChild(errorDiv);
            }
        </script>
        
        <div class="back-link">
            <a href="/">← Voltar ao início</a>
        </div>
    </div>
</body>
</html>
"#;

pub const ADMIN_HTML: &str = r#"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel Admin - SH.NET.BR</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
            line-height: 1.6;
        }
        .header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .content {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            margin: 0;
        }
        .logout-btn {
            background: #e74c3c;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .logout-btn:hover {
            background: #c0392b;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .section h2 {
            color: #34495e;
            margin-top: 0;
        }
        .upload-area {
            border: 2px dashed #3498db;
            padding: 40px;
            text-align: center;
            border-radius: 5px;
            background: #f8f9fa;
        }
        .script-list {
            margin-top: 20px;
        }
        .script-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            border: 1px solid #ddd;
            margin-bottom: 10px;
            border-radius: 5px;
            background: #f9f9f9;
        }
        .script-actions button {
            margin-left: 10px;
            padding: 5px 15px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        .sign-btn {
            background: #27ae60;
            color: white;
        }
        .delete-btn {
            background: #e74c3c;
            color: white;
        }
        .file-input {
            margin: 20px 0;
        }
        .upload-btn {
            background: #3498db;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .status {
            font-size: 0.9em;
            color: #7f8c8d;
        }
        .signed {
            color: #27ae60;
            font-weight: bold;
        }
        .unsigned {
            color: #e67e22;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛠️ Painel Administrativo</h1>
        <form method="post" action="/logout" style="margin: 0;">
            <button type="submit" class="logout-btn">Sair</button>
        </form>
    </div>

    <div class="content">
        <div class="section">
            <h2>📤 Upload de Scripts</h2>
            <form id="uploadForm" action="/admin/upload" method="post" enctype="multipart/form-data">
                <div class="upload-area">
                    <p>Selecione arquivos .sh para upload</p>
                    <input type="file" id="fileInput" name="script" accept=".sh" required class="file-input">
                    <br><br>
                    <button type="submit" class="upload-btn">Fazer Upload</button>
                </div>
            </form>
        </div>

        <div class="section">
            <h2>📋 Scripts Disponíveis</h2>
            <div id="scriptList" class="script-list">
                <!-- Lista de scripts será carregada aqui -->
            </div>
        </div>

        <div class="section">
            <h2>🔑 Chave GPG Pública</h2>
            <textarea id="publicKey" readonly style="width: 100%; height: 200px; font-family: monospace;">
                <!-- Chave pública será carregada aqui -->
            </textarea>
            <button onclick="copyPublicKey()" style="margin-top: 10px;" class="upload-btn">Copiar Chave</button>
        </div>
    </div>

    <script>
        // Carregar lista de scripts
        async function loadScripts() {
            try {
                const response = await fetch('/admin/scripts');
                const html = await response.text();
                document.getElementById('scriptList').innerHTML = html;
            } catch (error) {
                console.error('Erro ao carregar scripts:', error);
            }
        }

        // Assinar script
        async function signScript(scriptName) {
            try {
                const response = await fetch(`/admin/sign/${scriptName}`, {
                    method: 'POST'
                });
                
                if (response.ok) {
                    alert('Script assinado com sucesso!');
                    loadScripts();
                } else {
                    alert('Erro ao assinar script');
                }
            } catch (error) {
                console.error('Erro ao assinar script:', error);
                alert('Erro ao assinar script');
            }
        }

        // Copiar chave pública
        function copyPublicKey() {
            const textarea = document.getElementById('publicKey');
            textarea.select();
            document.execCommand('copy');
            alert('Chave pública copiada para a área de transferência!');
        }

        // Carregar scripts ao carregar a página
        document.addEventListener('DOMContentLoaded', loadScripts);
    </script>
</body>
</html>
"#;

pub fn render_script_list(scripts: &[ScriptInfo]) -> String {
    let mut html = String::new();
    
    if scripts.is_empty() {
        html.push_str("<p>Nenhum script encontrado.</p>");
        return html;
    }

    for script in scripts {
        let status_class = if script.signed { "signed" } else { "unsigned" };
        let status_text = if script.signed { "✅ Assinado" } else { "⚠️ Não assinado" };
        
        html.push_str(&format!(
            r#"
            <div class="script-item">
                <div>
                    <strong>{}</strong><br>
                    <span class="status">Tamanho: {} bytes | Hash: {}...</span><br>
                    <span class="status {}">{}</span>
                </div>
                <div class="script-actions">
                    <button class="sign-btn" onclick="signScript('{}')">🔏 Assinar</button>
                    <button class="delete-btn" onclick="deleteScript('{}')">🗑️ Remover</button>
                </div>
            </div>
            "#,
            script.name,
            script.size,
            &script.hash[..8],
            status_class,
            status_text,
            script.name,
            script.name
        ));
    }

    html
}
