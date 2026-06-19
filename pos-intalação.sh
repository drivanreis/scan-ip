# 1. Define o dono do executável do naabu como root
sudo chown root:root $(which naabu)

# 2. Dá o poder definitivo para ele manipular pacotes de rede brutos
sudo setcap cap_net_raw+ep $(which naabu)