#sudo nmap -p $(cat portas_vivas.txt | tr -d '\n' | tr -d ' ' | sed 's/,$//') -sV -T4 -v 192.168.1.25
#sudo nmap -p- -sS -T4 -v 192.168.1.25 -oN portas_vivas.txt
#sudo nmap -p 1-9999 -Pn -sT -T5 -v 192.168.1.25
#sudo nmap -p 1-9999 -Pn -sT -T5 -v 192.168.1.25 -oN portas_vivas.txt
#sudo nmap -sS -p 1-65535 -T1 -n -Pn 192.168.1.25 -oG scan_rapido.txt
#sudo nmap -sS -p $(cat listport.txt | tr -d '\n' | tr -d ' ' | sed 's/,$//') -T1 -n -Pn 192.168.1.25 -oG portas_vivas.txt

#naabu -host 192.168.1.25 -p 1-65535 -verify -rate 5000
#amap -Bv 192.168.1.25 1-5
#nikto -h http://192.168.1.25
#sudo apt update && sudo apt install naabu amap nikto -y