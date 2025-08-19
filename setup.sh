#!/bin/bash

# setup.sh - Script de configuração inicial para SH.NET.BR
set -euo pipefail

echo "🚀 Configurando SH.NET.BR..."

# Verificar dependências
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ Erro: $1 não está instalado"
        echo "   Por favor, instale $1 e execute este script novamente"
        exit 1
    fi
}

echo "🔍 Verificando dependências..."
check_dependency "rustc"
check_dependency "cargo"
check_dependency "gpg"

# Criar diretórios necessários
echo "📁 Criando estrutura de diretórios..."
mkdir -p scripts gpg_keys certs

# Verificar se já existe usuário admin
if [ -f "users.json" ]; then
    echo "👤 Arquivo de usuários já existe"
else
    echo "👤 Criando usuário administrativo padrão..."
    echo "   Usuário: admin"
    echo "   Senha: admin123"
    echo "   ⚠️  ALTERE A SENHA PADRÃO EM PRODUÇÃO!"
fi

# Compilar aplicação
echo "🔨 Compilando aplicação..."
if cargo build --release; then
    echo "✅ Compilação concluída com sucesso"
else
    echo "❌ Erro na compilação"
    exit 1
fi

# Verificar se GPG funciona
echo "🔐 Testando GPG..."
if gpg --version > /dev/null 2>&1; then
    echo "✅ GPG funcionando corretamente"
else
    echo "❌ Erro: GPG não está funcionando corretamente"
    exit 1
fi

# Criar script de exemplo se não existir
if [ ! -f "scripts/test.sh" ]; then
    echo "📝 Criando script de exemplo..."
    cat > scripts/test.sh << 'EOF'
#!/bin/bash
echo "🎉 Olá do SH.NET.BR!"
echo "Este é um script de teste servido pelo servidor"
echo "Executado em: $(date)"
echo "Sistema: $(uname -s)"
echo "Usuário: $(whoami)"
EOF
    chmod +x scripts/test.sh
fi

echo ""
echo "🎉 Configuração concluída!"
echo ""
echo "Para iniciar o servidor:"
echo "  cargo run"
echo ""
echo "Ou usar o binário compilado:"
echo "  ./target/release/sh_net_br"
echo ""
echo "O servidor estará disponível em:"
echo "  https://localhost:8443"
echo ""
echo "Painel administrativo:"
echo "  https://localhost:8443/admin"
echo "  Usuário: admin"
echo "  Senha: admin123"
echo ""
echo "⚠️  IMPORTANTE:"
echo "   • Altere a senha padrão em produção"
echo "   • Configure certificados válidos para uso público"
echo "   • Execute atrás de um proxy reverso (CloudFlare/Nginx)"
echo ""
echo "📚 Consulte o README.md para mais informações"
