#!/bin/bash

# Trava de segurança root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] erro: este script precisa ser executado como root (use sudo)."
    exit 1
fi

# Variáveis globais configuráveis
TARGET="138.122.82.214"  # IP alvo (pode ser alterado conforme necessário)
PORT_FILE="listport.txt"
TEMP_OUTPUT="portas_vivas.txt"

# Validação se o arquivo de portas existe
if [ ! -f "$PORT_FILE" ]; then
    echo "Erro: Arquivo $PORT_FILE não encontrado."
    exit 1
fi

echo "[*] Iniciando escaneamento furtivo contra $TARGET"

# ETAPA 1: SCAN FURTIVO E FOCADO (DESCOBERTA)
echo "[*] ETAPA 1: Convertendo lista de portas e realizando scan de descoberta..."

# Converter lista de portas para formato separado por vírgulas (removendo vírgulas existentes e espaços)
PORTS=$(cat "$PORT_FILE" | tr -d ',' | tr '\n' ',' | sed 's/,$//')

# Executar scan TCP SYN furtivo com feedback visual
nmap -sS -n -Pn -T3 --max-rate 15 -vv --stats-every 5s -p "$PORTS" -oG "$TEMP_OUTPUT" "$TARGET"

if [ ! -f "$TEMP_OUTPUT" ]; then
    echo "Erro: Falha ao gerar arquivo de saída do scan."
    exit 1
fi

# Depuração: verificar se arquivo temporário está vazio
if [ ! -s "$TEMP_OUTPUT" ]; then
    echo "[!] Arquivo temporário vazio. Conteúdo gerado:"
    cat "$TEMP_OUTPUT"
    rm -f "$TEMP_OUTPUT"
    exit 1
fi

echo "[*] Scan de descoberta concluído."

# ETAPA 2: EXTRAÇÃO TÉCNICA E ANÁLISE PROFUNDA
echo "[*] ETAPA 2: Extraindo portas abertas para análise detalhada..."

# Extrair portas com status "open" do arquivo grepable
PORTAS_FILTRADAS=$(grep "Ports:" "$TEMP_OUTPUT" | grep -oE '[0-9]+/open' | cut -d'/' -f1 | paste -sd,)

if [ -z "$PORTAS_FILTRADAS" ]; then
    echo "[!] Nenhuma porta aberta encontrada."
    echo "[!] Conteúdo do arquivo temporário para depuração:"
    cat "$TEMP_OUTPUT"
    rm -f "$TEMP_OUTPUT"
    exit 0
fi

# Trava de segurança contra honeypot/port spoofing
NUM_PORTAS=$(echo "$PORTAS_FILTRADAS" | tr -cd ',' | wc -c)
((NUM_PORTAS++))  # adiciona 1 para contar a última porta

if [ "$NUM_PORTAS" -gt 20 ]; then
    echo "[-] aviso: o alvo detectou o scan e está gerando falsos positivos ($NUM_PORTAS portas abertas detectadas)."
    echo "[-] para sua segurança, a ETAPA 2 será executada limitando a análise apenas às primeiras 5 portas reais encontradas."
    PORTAS_FILTRADAS=$(echo "$PORTAS_FILTRADAS" | cut -d',' -f1-5)
fi

echo "[*] Portas abertas detectadas: $PORTAS_FILTRADAS"
echo "[*] Iniciando análise profunda de serviços..."

# Executar scan detalhado de serviços nas portas filtradas
nmap -p "$PORTAS_FILTRADAS" -sV -T4 -v "$TARGET"

# Limpeza
rm -f "$TEMP_OUTPUT"
echo "[*] Escaneamento concluído."
