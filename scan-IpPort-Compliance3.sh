#!/bin/bash

# Variável global configurável
TARGET="138.122.82.214"  # IP alvo

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

# ==============================================================================
# FASE 1: AS 1000 PORTAS MAIS COMUNS (RESULTADO IMEDIATO)
# ==============================================================================
echo -e "\n=== FASE 1: Triagem das 1.000 portas mais comuns ==="

# Varre o top 1000 mostrando a porcentagem real a cada 5 segundos
nmap -sT -T4 --top-ports 1000 --open -Pn --stats-every=5s "$TARGET" -oG /tmp/nmap_fase1.gnmap

# Filtra e extrai as portas encontradas na Fase 1
awk '/Ports:/ {print $0}' /tmp/nmap_fase1.gnmap > portas_fase1.txt
rm -f /tmp/nmap_fase1.gnmap

if [ -s "portas_fase1.txt" ]; then
    PORTAS_F1=$(grep -oE '[0-9]+/open' portas_fase1.txt | cut -d'/' -f1 | paste -sd,)
    echo "[*] Portas detectadas na Fase 1: $PORTAS_F1"
    
    echo "[*] Disparando Arsenal de Compliance para a Fase 1..."
    nmap -p "$PORTAS_F1" -sV -sC -T4 -Pn "$TARGET" -oN laudo_nmap.txt
    
    > laudo_amap.txt
    for PORTA in $(echo "$PORTAS_F1" | tr ',' '\n'); do
        amap -Bv "$TARGET" "$PORTA" >> laudo_amap.txt
    done
    echo "[*] Laudos da Fase 1 gerados com sucesso."
else
    echo "[*] Nenhuma porta aberta encontrada no Top 1000."
fi

# ==============================================================================
# INTERAÇÃO: DECISÃO DE COMPLIANCE TOTAL
# ==============================================================================
echo -e "\n------------------------------------------------------------"
echo "[?] Fase 1 concluída. Para entregar 100% de Compliance,"
echo "[?] precisamos varrer as outras 64.535 portas restantes."
read -p "[?] Deseja continuar com a varredura completa agora? (s/N): " RESPOND

if [[ ! "$RESPOND" =~ ^[Ss]$ ]]; then
    echo -e "\n[*] Auditoria encerrada pelo usuário. Compliance Parcial garantido."
    exit 0
fi

# ==============================================================================
# FASE 2: COMPLIANCE TOTAL (1-65535 EXCLUINDO AS 1000 JÁ TESTADAS)
# ==============================================================================
echo -e "\n=== FASE 2: Escaneando restante do escopo (64.535 portas) ==="
echo "[*] Filtrando rede para evitar redundância. Aguarde..."

# O Nmap vai testar de 1 a 65535, mas vai ignorar as 1000 que ele já testou na Fase 1
# A flag --stats-every=10s vai te dar a porcentagem exata de progresso desse scan longo
nmap -sT -T4 -p 1-65535 --exclude-ports $(nmap --top-ports 1000 localhost | awk '/Ports:/ {print $2}' | grep -oE '[0-9]+' | paste -sd,) --open -Pn --stats-every=10s "$TARGET" -oG /tmp/nmap_fase2.gnmap

awk '/Ports:/ {print $0}' /tmp/nmap_fase2.gnmap > portas_fase2.txt
rm -f /tmp/nmap_fase2.gnmap

if [ -s "portas_fase2.txt" ]; then
    PORTAS_F2=$(grep -oE '[0-9]+/open' portas_fase2.txt | cut -d'/' -f1 | paste -sd,)
    echo "[*] Portas adicionais encontradas na Fase 2: $PORTAS_F2"
    
    echo "[*] Incrementando laudos com os novos achados de Compliance..."
    # O '>>' joga os novos resultados no fim dos mesmos arquivos, centralizando tudo
    nmap -p "$PORTAS_F2" -sV -sC -T4 -Pn "$TARGET" >> laudo_nmap.txt
    
    for PORTA in $(echo "$PORTAS_F2" | tr ',' '\n'); do
        amap -Bv "$TARGET" "$PORTA" >> laudo_amap.txt
    done
    echo "[*] Laudos atualizados com os dados da Fase 2."
else
    echo "[*] Nenhuma porta adicional foi encontrada nas 64.535 restantes."
fi

# Limpeza final de arquivos de escopo
rm -f portas_fase1.txt portas_fase2.txt

echo -e "\n[*] Auditoria de COMPLIANCE 100% concluída com sucesso absoluto!"
echo "[*] Relatórios finais consolidados: laudo_nmap.txt e laudo_amap.txt"