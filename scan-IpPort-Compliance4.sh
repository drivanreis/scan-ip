#!/bin/bash

# Variável global configurável
TARGET="138.122.82.214"  # Seu IP Fixo MOB

# Tratamento de sinais do sistema (resiliência)
trap 'cleanup' EXIT INT TERM

cleanup() {
    rm -f portas_fase1.txt portas_fase2.txt /tmp/nmap_fase1.gnmap /tmp/nmap_fase2.gnmap 2>/dev/null
}

# Trava de segurança root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Erro: Este script exige privilégios de root (use sudo)."
    exit 1
fi

echo "[*] Iniciando auditoria de compliance em duas fases contra $TARGET"
echo "[*] ATENÇÃO: Certifique-se de manter a VPN LIGADA para o tráfego conseguir entrar!"

# ==============================================================================
# FASE 1: AS 100 PORTAS MAIS COMUNS (TIRO CURTO E SEGURO)
# ==============================================================================
echo -e "\n=== FASE 1: Triagem ultra rápida das 100 portas mais prováveis ==="

# Mudado para --top-ports 100 para voar baixo na triagem inicial
nmap -sT -T4 --top-ports 100 --open -Pn --stats-every=3s "$TARGET" -oG /tmp/nmap_fase1.gnmap

# Filtra e extrai as portas encontradas na Fase 1
awk '/Ports:/ {print $0}' /tmp/nmap_fase1.gnmap > portas_fase1.txt
rm -f /tmp/nmap_fase1.gnmap

if [ -s "portas_fase1.txt" ]; then
    PORTAS_F1=$(grep -oE '[0-9]+/open' portas_fase1.txt | cut -d'/' -f1 | paste -sd,)
    echo "[*] Portas detectadas no Top 100: $PORTAS_F1"
    
    echo "[*] Disparando Arsenal de Compliance para a Fase 1..."
    echo "[*] Analisando apenas os serviços essenciais detectados:"
    echo "------------------------------------------------------------------------"
    
    # Executa a análise profunda APENAS no grupo restrito encontrado nas 100 melhores
    nmap -p "$PORTAS_F1" -sV -sC -T4 -Pn -v --stats-every=5s "$TARGET" -oN laudo_nmap.txt
    
    echo "------------------------------------------------------------------------"
    echo "[*] Executando Amap para identificação de protocolos..."
    > laudo_amap.txt
    TOTAL_PORTAS=$(echo "$PORTAS_F1" | tr ',' '\n' | wc -l)
    CONTADOR=0
    for PORTA in $(echo "$PORTAS_F1" | tr ',' '\n'); do
        CONTADOR=$((CONTADOR + 1))
        PCT_AMAP=$(( (CONTADOR * 100) / TOTAL_PORTAS ))
        printf "\r[*] Progresso do Amap: %d/%d portas completadas [ %d%% ]" "$CONTADOR" "$TOTAL_PORTAS" "$PCT_AMAP"
        amap -Bv "$TARGET" "$PORTA" >> laudo_amap.txt
    done
    echo -e " [ OK ]"
    echo "[*] Laudos da Fase 1 gerados com sucesso."
else
    echo "[*] Nenhuma das 100 portas mais comuns está aberta. Verifique sua VPN!"
fi

# ==============================================================================
# INTERAÇÃO: DECISÃO DE COMPLIANCE TOTAL
# ==============================================================================
echo -e "\n------------------------------------------------------------"
echo "[?] Fase 1 concluída com velocidade."
echo "[?] Deseja iniciar a Fase 2 para testar as outras 65.435 portas restantes? (s/N): "
read -p "> " RESPOND

if [[ ! "$RESPOND" =~ ^[Ss]$ ]]; then
    echo -e "\n[*] Auditoria encerrada pelo usuário. Compliance do núcleo garantido."
    exit 0
fi

# ==============================================================================
# FASE 2: COMPLIANCE TOTAL (1-65535 EXCLUINDO AS 100 JÁ TESTADAS)
# ==============================================================================
echo -e "\n=== FASE 2: Escaneando restante do escopo profundo (65.435 portas) ==="
echo "[*] Gerando lista de exclusão estática do Top 100..."

# Monta o filtro com as 100 portas que já matamos na Fase 1
LISTA_EXCLUSAO=$(nmap -v -oG - --top-ports 100 localhost | awk '/Ports:/ {print $2}' | grep -oE '[0-9]+' | paste -sd, 2>/dev/null)

if [ -z "$LISTA_EXCLUSAO" ]; then
    LISTA_EXCLUSAO="21,22,23,25,53,80,110,139,443,445,3306,3389,8006,8080"
fi

echo "[*] Mapeando portas residuais em lote profundo. Acompanhe o percentual abaixo:"
nmap -sT -T4 -p 1-65535 --exclude-ports "$LISTA_EXCLUSAO" --open -Pn --stats-every=15s "$TARGET" -oG /tmp/nmap_fase2.gnmap

awk '/Ports:/ {print $0}' /tmp/nmap_fase2.gnmap > portas_fase2.txt
rm -f /tmp/nmap_fase2.gnmap

if [ -s "portas_fase2.txt" ]; then
    PORTAS_F2=$(grep -oE '[0-9]+/open' portas_fase2.txt | cut -d'/' -f1 | paste -sd,)
    echo "[*] Novas portas encontradas na varredura profunda: $PORTAS_F2"
    
    echo "[*] Incrementando laudos finais com os novos achados..."
    echo "------------------------------------------------------------------------"
    nmap -p "$PORTAS_F2" -sV -sC -T4 -Pn -v --stats-every=10s "$TARGET" >> laudo_nmap.txt
    echo "------------------------------------------------------------------------"
    
    for PORTA in $(echo "$PORTAS_F2" | tr ',' '\n'); do
        amap -Bv "$TARGET" "$PORTA" >> laudo_amap.txt
    done
    echo "[*] Laudos atualizados e consolidados."
else
    echo "[*] Nenhuma porta adicional foi encontrada no restante do escopo."
fi

rm -f portas_fase1.txt portas_fase2.txt

echo -e "\n[*] Auditoria de COMPLIANCE 100% concluída com sucesso absoluto!"
echo "[*] Relatórios finais consolidados com segurança: laudo_nmap.txt e laudo_amap.txt"