# SH.NET.BR - Servidor Seguro de Scripts Bash

Um servidor web em Rust para distribuir scripts bash de forma segura com autenticação, verificação de integridade e assinaturas GPG.

## 🚀 Características

- **HTTPS Obrigatório**: Certificados TLS autoassinados renovados a cada reinicialização
- **Múltiplos Formatos de URL**:
  - `sh.net.br/script.sh`
  - `script.sh.net.br`
  - `sh.net.br/scripts/script.sh`
- **Verificação de Integridade**: Hash SHA-256 para todos os scripts
- **Assinaturas GPG**: Suporte completo para assinatura e verificação digital
- **Autenticação Segura**: Sistema de login com JWT e sessões
- **Interface Web**: Painel administrativo para gerenciar scripts
- **Compatibilidade CloudFlare**: Funciona perfeitamente atrás de proxy

## 📋 Pré-requisitos

- Rust 1.70+
- GPG instalado no sistema
- OpenSSL/LibreSSL

### Instalar dependências no Ubuntu/Debian:

```bash
sudo apt update
sudo apt install gnupg2 openssl pkg-config libssl-dev
```

### Instalar dependências no CentOS/RHEL:

```bash
sudo yum install gnupg2 openssl-devel pkgconfig
```

## 🛠️ Instalação e Configuração

1. **Clone e compile:**

```bash
git clone <repo>
cd sh_net_br
cargo build --release
```

2. **Configurar usuário administrativo:**

O sistema cria automaticamente um usuário `admin` com senha `admin123`. Você deve alterar isso imediatamente em produção.

3. **Executar:**

```bash
cargo run
```

O servidor iniciará em `https://localhost:8443`

## 📁 Estrutura de Diretórios

```
sh_net_br/
├── scripts/          # Scripts .sh servidos
├── gpg_keys/         # Chaves GPG do servidor
├── certs/            # Certificados TLS (gerados automaticamente)
├── templates/        # Templates HTML
└── src/              # Código fonte
```

## 🔧 Uso

### Servir Scripts

1. Coloque arquivos `.sh` no diretório `scripts/`
2. Acesse via:
   - `https://sh.net.br/meu-script.sh`
   - `https://meu-script.sh.net.br`
   - `https://sh.net.br/scripts/meu-script.sh`

### Verificação de Hash

```bash
# Obter hash do script
curl -I https://sh.net.br/test.sh | grep X-Content-Hash

# Baixar com verificação de hash
curl "https://sh.net.br/test.sh?hash=abc123..."

# Hash inválido retorna erro 400
```

### Assinatura GPG

```bash
# Baixar script com verificação de assinatura
curl "https://sh.net.br/test.sh?verify=true"

# Baixar arquivo de assinatura
curl https://sh.net.br/test.sh.sig

# Verificar manualmente
gpg --verify test.sh.sig test.sh
```

### API REST

```bash
# Informações de um script
curl https://sh.net.br/api/script/test.sh/info

# Lista todos os scripts
curl https://sh.net.br/api/scripts
```

## 🔐 Segurança

### HTTPS Obrigatório

- Certificados TLS autoassinados gerados automaticamente
- Renovação a cada reinicialização
- Compatível com CloudFlare para validação externa

### Autenticação

- Sistema de login com bcrypt para senhas
- JWT para tokens de sessão
- Sessões expiram em 1 hora
- Cookies seguros (HttpOnly, Secure, SameSite)

### GPG

- Chaves RSA 4096 bits
- Assinaturas destacadas (.sig)
- Repositório de chaves público
- Verificação automática opcional

## 🌐 Configuração CloudFlare

1. Configure o CloudFlare para proxy o tráfego
2. Defina SSL/TLS como "Full (strict)" ou "Flexible"
3. O servidor gerará certificados válidos automaticamente
4. Configure redirects se necessário:
   - `*.sh.net.br` → `sh.net.br/$1.sh`

## 🔧 Painel Administrativo

Acesse `https://sh.net.br/admin` com credenciais de administrador:

- **Upload de Scripts**: Interface para enviar novos scripts
- **Gerenciar Assinaturas**: Assinar scripts com GPG
- **Visualizar Chave Pública**: Exportar chave GPG do servidor
- **Listar Scripts**: Ver todos os scripts e seus status

## 📊 Logs e Monitoramento

O servidor usa `tracing` para logging estruturado:

```bash
# Executar com logs detalhados
RUST_LOG=debug cargo run

# Logs em produção
RUST_LOG=info cargo run
```

## 🚀 Deployment

### Docker (Recomendado)

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y gnupg2 ca-certificates
COPY --from=builder /app/target/release/sh_net_br /usr/local/bin/
EXPOSE 8443
CMD ["sh_net_br"]
```

### Systemd Service

```ini
[Unit]
Description=SH.NET.BR Server
After=network.target

[Service]
Type=simple
User=shnetbr
WorkingDirectory=/opt/sh_net_br
ExecStart=/opt/sh_net_br/sh_net_br
Restart=always
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

## 🔒 Alterando Credenciais Padrão

```bash
# Editar users.json manualmente ou usar a API administrativa
echo '{"admin": "$2b$12$hash..."}' > users.json
```

## 🐛 Troubleshooting

### GPG não encontrado

```bash
# Verificar instalação
gpg --version

# Instalar se necessário
sudo apt install gnupg2
```

### Erro de certificado TLS

- Verifique se o diretório `certs/` tem permissões de escrita
- Certificados são regenerados automaticamente a cada reinício

### Scripts não encontrados

- Verifique se os arquivos estão em `scripts/`
- Certifique-se de que têm extensão `.sh`
- Verifique permissões de leitura

## 📄 Licença

MIT License - veja arquivo LICENSE para detalhes.

## 🤝 Contribuindo

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📞 Suporte

Para suporte e dúvidas, abra uma issue no repositório.
