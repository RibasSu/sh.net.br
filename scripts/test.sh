#!/bin/bash

# Script de teste para SH.NET.BR
# Este é um exemplo de script bash que pode ser servido pelo servidor

echo "🚀 Olá do SH.NET.BR!"
echo "Este script foi baixado de: ${BASH_SOURCE[0]}"
echo "Executado em: $(date)"
echo "Usuário: $(whoami)"
echo "Sistema: $(uname -s)"

# Verificar se estamos executando com verificação de hash
if [ ! -z "$SH_NET_BR_HASH" ]; then
    echo "✅ Hash verificado: $SH_NET_BR_HASH"
fi

# Verificar se o script foi assinado
if [ ! -z "$SH_NET_BR_SIGNED" ]; then
    echo "🔐 Script assinado digitalmente"
fi

echo ""
echo "📋 Comandos úteis:"
echo "  • Verificar hash: curl -I https://sh.net.br/test.sh | grep X-Content-Hash"
echo "  • Baixar assinatura: curl https://sh.net.br/test.sh.sig"
echo "  • Executar com verificação: curl -s 'https://sh.net.br/test.sh?verify=true' | bash"

echo ""
echo "✨ Script executado com sucesso!"
