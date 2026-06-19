#!/bin/bash

# Variável global configurável
TARGET="138.122.82.214"  # IP alvo (pode ser alterado conforme necessário)

# Tratamento de sinais do sistema (resiliência)
trap 'rm -f portas_reais.txt' EXIT INT TERM

# Trava de segurança root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Erro: Este script exige privilégios de root (use sudo)."
    exit 1
fi

# Garante portabilidade configurando as capabilities do Naabu automaticamente
# Abordagem A: Localizar binário real e configurar capabilities
CAMINHO_NAABU=$(which naabu)
if [ -n "$CAMINHO_NAABU" ]; then
    # Tentar obter caminho absoluto real (resolvendo symlinks)
    CAMINHO_REAL=$(readlink -f "$CAMINHO_NAABU" 2>/dev/null)
    if [ -n "$CAMINHO_REAL" ] && [ -f "$CAMINHO_REAL" ]; then
        CAMINHO_NAABU="$CAMINHO_REAL"
    fi
    chown root:root "$CAMINHO_NAABU" 2>/dev/null
    setcap cap_net_raw+ep "$CAMINHO_NAABU" 2>/dev/null
fi

# Abordagem B: Se capabilities falharem, baixar binário puro do GitHub
NAABU_PURE="/usr/local/bin/naabu-pure"
if [ ! -f "$NAABU_PURE" ]; then
    echo "[*] Baixando binário puro do Naabu do GitHub (v2.6.1)..."
    wget -q https://github.com/projectdiscovery/naabu/releases/download/v2.6.1/naabu_2.6.1_linux_amd64.zip -O /tmp/naabu.zip 2>/dev/null || {
        echo "[!] Erro ao baixar Naabu puro. Usando versão do sistema."
    }
    if [ -f "/tmp/naabu.zip" ]; then
        unzip -q -o /tmp/naabu.zip -d /tmp/
        if [ -f "/tmp/naabu" ]; then
            mv /tmp/naabu "$NAABU_PURE"
            chmod +x "$NAABU_PURE"
            chown root:root "$NAABU_PURE"
            setcap cap_net_raw+ep "$NAABU_PURE"
            echo "[*] Binário puro instalado em $NAABU_PURE"
        fi
        rm -f /tmp/naabu.zip /tmp/naabu
    fi
fi

# Determinar qual binário usar (prioridade para binário puro)
if [ -f "$NAABU_PURE" ]; then
    COMANDO_NAABU="$NAABU_PURE"
else
    COMANDO_NAABU="$CAMINHO_NAABU"
fi

echo "[*] Iniciando auditoria de compliance contra $TARGET"

# ETAPA 1: PERFURAÇÃO DE FIREWALL (NAABU)
echo "[*] ETAPA 1: Perfurando firewall com naabu (varredura 1-65535)..."
echo "[*] Usando binário: $COMANDO_NAABU"

# Executar com flag explícita -scan-type syn para forçar SYN scan e capturar saída para validação
SAIDA_NAABU=$($COMANDO_NAABU -host "$TARGET" -p 1-65535 --rate 1000 -verify -scan-type syn -o portas_reais.txt 2>&1)

# Validação estrita: verificar se caiu em CONNECT scan (sem privilégios)
if echo "$SAIDA_NAABU" | grep -q "Running CONNECT scan with non root privileges"; then
    echo "[!] ALERTA: Naabu caiu em CONNECT scan (sem privilégios root)"
    echo "[!] Tentando executar como root real..."
    
    # Tentar executar como root real usando sudo -S com senha
    SAIDA_NAABU=$(echo "123" | sudo -S $COMANDO_NAABU -host "$TARGET" -p 1-65535 --rate 1000 -verify -scan-type syn -o portas_reais.txt 2>&1)
    
    if echo "$SAIDA_NAABU" | grep -q "Running CONNECT scan with non root privileges"; then
        echo "[!] FALHA: Mesmo como root real, caiu em CONNECT scan"
        echo "[!] Aceitando CONNECT scan como fallback (será mais lento, mas funcional)..."
        SAIDA_NAABU=$($COMANDO_NAABU -host "$TARGET" -p 1-65535 --rate 1000 -verify -o portas_reais.txt 2>&1)
        echo "[*] Executando CONNECT scan (modo lento, mas funcional)"
    else
        echo "[*] SUCESSO: SYN scan com root privileges ativado"
    fi
else
    echo "[*] SUCESSO: SYN scan com root privileges ativado"
fi

if [ ! -f "portas_reais.txt" ]; then
    echo "[!] Erro: Falha ao gerar arquivo de portas."
    exit 1
fi

echo "[*] Perfuração de firewall concluída."

# ETAPA 2: VALIDAÇÃO DO ESCOPO
echo "[*] ETAPA 2: Validando escopo de portas..."

if [ ! -s "portas_reais.txt" ]; then
    echo "[!] Nenhuma porta real encontrada ou o host está offline."
    rm -f "portas_reais.txt"
    exit 0
fi

# Converter portas para formato separado por vírgulas (extrair apenas número da porta do formato IP:PORTA)
PORTAS_CONCRETAS=$(awk -F: '{print $NF}' portas_reais.txt | paste -sd,)

echo "[*] Portas reais detectadas: $PORTAS_CONCRETAS"

# Validação de debug
echo "DEBUG TARGET=[$TARGET]"
echo "DEBUG PORTAS=[$PORTAS_CONCRETAS]"

# ETAPA 3: ARSENAL DE COMPLIANCE (NMAP & AMAP)
echo "[*] ETAPA 3: Executando arsenal de compliance..."

# Executar Nmap
echo "[*] Executando Nmap para análise de serviços e scripts..."
nmap -p "$PORTAS_CONCRETAS" -sV -sC -T4 -Pn -v "$TARGET" -oN laudo_nmap.txt

# Executar Amap (processando porta por porta)
echo "[*] Executando Amap para mapeamento de aplicações..."
> laudo_amap.txt
while read -r LINHA; do
    PORTA=$(echo "$LINHA" | awk -F: '{print $NF}')
    amap -Bv "$TARGET" "$PORTA" >> laudo_amap.txt
done < portas_reais.txt

# Limpeza (o trap já cuida do arquivo temporário, mas mantemos para clareza)
rm -f "portas_reais.txt"

echo "[*] Auditoria de compliance concluída com sucesso."
echo "[*] Relatórios gerados: laudo_nmap.txt e laudo_amap.txt"
