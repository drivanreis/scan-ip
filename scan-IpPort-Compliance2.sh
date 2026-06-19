#!/bin/bash

# Variável global configurável
TARGET="138.122.82.214"  # IP alvo

# Tratamento de sinais do sistema (resiliência)
trap 'cleanup' EXIT INT TERM

cleanup() {
    # Garante que o spinner morra se o script for interrompido
    if [ -n "$SPINNER_PID" ] && kill -0 "$SPINNER_PID" 2>/dev/null; then
        kill "$SPINNER_PID" 2>/dev/null
    fi
    # Restaura o cursor piscando na tela
    tput cnorm 2>/dev/null
    rm -f portas_reais.txt /tmp/naabu_exec.log
}

# FUNÇÃO DO SPINNER ATUALIZADA (Indicador de Progresso com Percentual)
start_spinner() {
    local MENSAGEM="$1"
    # Esconde o cursor do terminal para a animação ficar limpa
    tput civis 2>/dev/null
    
    (
        local delay=0.1
        local spinstr='|/-\'
        local pct=0
        local count=0
        
        while true; do
            # Sobe o percentual gradualmente baseado no tempo estimado para a taxa 500 (~131 segundos)
            # 131 segundos * 10 iterações por segundo = ~1310 iterações totais.
            # Incrementamos 1% a cada 13 iterações para dar uma estimativa real da varredura.
            count=$((count + 1))
            if [ $((count % 13)) -eq 0 ] && [ $pct -lt 99 ]; then
                pct=$((pct + 1))
            fi

            local temp=${spinstr#?}
            # Exibe a mensagem original, o spinner rodando e o percentual dinâmico
            printf "\r%s [%c] [ %d%% ]" "$MENSAGEM" "$spinstr" "$pct"
            local spinstr=$temp${spinstr%"$temp"}
            sleep $delay
        done
    ) &
    SPINNER_PID=$!
}

stop_spinner() {
    if [ -n "$SPINNER_PID" ] && kill -0 "$SPINNER_PID" 2>/dev/null; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null
    fi
    # Limpa o final da linha e bota o OK verde
    printf "\r\033[K"
    echo -e "[*] Varredura finalizada com sucesso! [ OK ]"
    # Restaura o cursor
    tput cnorm 2>/dev/null
}

# Trava de segurança root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Erro: Este script exige privilégios de root (use sudo)."
    exit 1
fi

# Garante portabilidade configurando as capabilities do Naabu automaticamente
CAMINHO_NAABU=$(which naabu)
if [ -n "$CAMINHO_NAABU" ]; then
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

if [ -f "$NAABU_PURE" ]; then
    COMANDO_NAABU="$NAABU_PURE"
else
    COMANDO_NAABU="$CAMINHO_NAABU"
fi

echo "[*] Iniciando auditoria de compliance contra $TARGET"

# ETAPA 1: PERFURAÇÃO DE FIREWALL (NAABU)
echo "[*] ETAPA 1: Perfurando firewall com naabu (varredura 1-65535)..."
echo "[*] Usando binário: $COMANDO_NAABU"

# Liga o Spinner animado antes de começar a travar o terminal
start_spinner "[*] Varrendo 65535 portas via SYN Scan (Aguarde...)"

# Executa o comando jogando a saída para um arquivo temporário em vez de reter na variável travada
$COMANDO_NAABU -host "$TARGET" -p 1-65535 --rate 500 -verify -scan-type syn -o portas_reais.txt > /tmp/naabu_exec.log 2>&1
SAIDA_NAABU=$(cat /tmp/naabu_exec.log)

# Desliga o Spinner
stop_spinner

# Validação estrita: verificar se caiu em CONNECT scan
if echo "$SAIDA_NAABU" | grep -q "Running CONNECT scan with non root privileges"; then
    echo "[!] ALERTA: Naabu caiu em CONNECT scan (sem privilégios root)"
    
    start_spinner "[!] Tentando executar forçado como root real..."
    SAIDA_NAABU=$(echo "123" | sudo -S $COMANDO_NAABU -host "$TARGET" -p 1-65535 --rate 500 -verify -scan-type syn -o portas_reais.txt 2>&1)
    stop_spinner
    
    if echo "$SAIDA_NAABU" | grep -q "Running CONNECT scan with non root privileges"; then
        echo "[!] FALHA: Mesmo como root real, caiu em CONNECT scan."
        
        start_spinner "[*] Iniciando Fallback CONNECT Scan (Modo lento)..."
        $COMANDO_NAABU -host "$TARGET" -p 1-65535 --rate 500 -verify -o portas_reais.txt > /tmp/naabu_exec.log 2>&1
        stop_spinner
    else
        echo "[*] SUCESSO: SYN scan com root privileges ativado."
    fi
else
    echo "[*] SUCESSO: SYN scan com root privileges ativado."
fi

if [ ! -f "portas_reais.txt" ]; then
    echo "[!] Erro: Falha ao gerar arquivo de portas."
    exit 1
fi

# ETAPA 2: VALIDAÇÃO DO ESCOPO
echo "[*] ETAPA 2: Validando escopo de portas..."
if [ ! -s "portas_reais.txt" ]; then
    echo "[!] Nenhuma porta real encontrada ou o host está offline."
    rm -f "portas_reais.txt"
    exit 1
fi

PORTAS_CONCRETAS=$(awk -F: '{print $NF}' portas_reais.txt | paste -sd,)
echo "[*] Portas reais detectadas: $PORTAS_CONCRETAS"

# ETAPA 3: ARSENAL DE COMPLIANCE (NMAP & AMAP)
echo "[*] ETAPA 3: Executando arsenal de compliance..."

# O Nmap em modo verbose (-v) já joga o progresso nativamente na tela a cada poucos segundos
echo "[*] Executando Nmap para análise de serviços e scripts (Acompanhe abaixo):"
nmap -p "$PORTAS_CONCRETAS" -sV -sC -T4 -Pn -v "$TARGET" -oN laudo_nmap.txt

echo "[*] Executando Amap para mapeamento de aplicações..."
start_spinner "[*] Amap processando assinaturas nas portas encontradas..."
> laudo_amap.txt
while read -r LINHA; do
    PORTA=$(echo "$LINHA" | awk -F: '{print $NF}')
    amap -Bv "$TARGET" "$PORTA" >> laudo_amap.txt
done < portas_reais.txt
stop_spinner

rm -f "portas_reais.txt" /tmp/naabu_exec.log

echo "[*] Auditoria de compliance concluída com sucesso."
echo "[*] Relatórios gerados: laudo_nmap.txt e laudo_amap.txt"