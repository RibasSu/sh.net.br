# Dockerfile para SH.NET.BR
FROM rust:1.70-bookworm as builder

# Instalar dependências de build
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    gnupg2 \
    && rm -rf /var/lib/apt/lists/*

# Configurar diretório de trabalho
WORKDIR /app

# Copiar arquivos de configuração primeiro (para cache de dependências)
COPY Cargo.toml Cargo.lock ./

# Criar src/main.rs temporário para build das dependências
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build das dependências
RUN cargo build --release && rm -rf src

# Copiar código fonte real
COPY src/ src/

# Build da aplicação
RUN touch src/main.rs && cargo build --release

# Imagem de produção
FROM debian:bookworm-slim

# Instalar dependências de runtime
RUN apt-get update && apt-get install -y \
    gnupg2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Criar usuário não-root
RUN useradd -r -s /bin/false shnetbr

# Criar diretórios necessários
RUN mkdir -p /opt/sh_net_br/{scripts,gpg_keys,certs} && \
    chown -R shnetbr:shnetbr /opt/sh_net_br

# Copiar binário
COPY --from=builder /app/target/release/sh_net_br /usr/local/bin/sh_net_br
RUN chmod +x /usr/local/bin/sh_net_br

# Copiar script de exemplo
COPY scripts/test.sh /opt/sh_net_br/scripts/

# Configurar usuário e diretório de trabalho
USER shnetbr
WORKDIR /opt/sh_net_br

# Expor porta HTTPS
EXPOSE 8443

# Definir variáveis de ambiente
ENV RUST_LOG=info

# Comando de início
CMD ["sh_net_br"]
