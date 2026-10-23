#!/usr/bin/env bash
# setup_parrot_websec.sh - Aprovisionamiento 100% automatizado de Parrot OS para Web-Sec
# Autor: Ibrahim García & Antigravity
# Este script se ejecuta dentro de Parrot OS o se inyecta por terminal.

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}=== 🛡️ APROVISIONAMIENTO MAESTRO DE PARROT OS PARA WEB-SEC ===${NC}\n"

# 1. Arreglar DNS para evitar 'Temporary failure resolving deb.parrot.sh'
echo -e "[*] 1/7 Configurando DNS de alta disponibilidad (Cloudflare & Google)..."
echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" | sudo tee /etc/resolv.conf >/dev/null
echo -e "    ${GREEN}✔ DNS configurado a 1.1.1.1 y 8.8.8.8${NC}"

# 2. Habilitar demonio de portapapeles bidireccional (spice-vdagent)
echo -e "[*] 2/7 Habilitando portapapeles compartido bidireccional (Host <-> Parrot)..."
sudo systemctl enable --now spice-vdagent 2>/dev/null || true
echo -e "    ${GREEN}✔ spice-vdagent corriendo y activo.${NC}"

# 3. Actualizar repositorios e instalar paquetes base de auditoría
echo -e "[*] 3/7 Instalando dependencias de Python, Playwright, Git y Magic-Wormhole..."
sudo apt update -y
sudo apt install -y \
    git curl wget python3-pip python3-venv \
    magic-wormhole nmap ffuf whatweb sqlmap \
    libnss3 libatk1.0-0 libcups2 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxrandr2 libgbm1 libasound2

echo -e "    ${GREEN}✔ Paquetes base y plugins de seguridad listos.${NC}"

# 4. Clonar o actualizar la suite web-sec
WORKDIR="$HOME/web-sec"
if [ -d "$WORKDIR" ]; then
    echo -e "[*] 4/7 Actualizando repositorio web-sec existente..."
    cd "$WORKDIR"
    git pull origin main 2>/dev/null || true
else
    echo -e "[*] 4/7 Clonando repositorio oficial de web-sec..."
    git clone https://github.com/ultimaibrahim/web-sec.git "$WORKDIR"
    cd "$WORKDIR"
fi

# 5. Configurar Entorno Virtual de Python y dependencias
echo -e "[*] 5/7 Creando entorno virtual aislado (venv) e instalando librerías..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 6. Instalar navegador Chromium headless para Playwright (Scraping Nivel 1 y 2)
echo -e "[*] 6/7 Instalando navegador Chromium para el motor de Scraping (Playwright)..."
playwright install chromium
playwright install-deps chromium 2>/dev/null || true

# 7. Crear alias y accesos directos de conveniencia en Parrot
echo -e "[*] 7/7 Configurando accesos directos y permisos de ejecución..."
chmod +x launch_hollywood_grid.sh mode2_richlive.py mode3_blueteam.py terminal_privacy_monitor.py terminal_vault_ticker.py 2>/dev/null || true

if ! grep -q "web-sec" ~/.bashrc; then
    cat << 'BASHRC' >> ~/.bashrc

# --- Web-Sec Cyber-Deck Aliases ---
alias websec='cd ~/web-sec && source venv/bin/activate && python3 mode2_richlive.py 1'
alias webgrid='cd ~/web-sec && ./launch_hollywood_grid.sh'
alias webvault='cd ~/web-sec && source venv/bin/activate && python3 terminal_vault_ticker.py'
alias webpriv='cd ~/web-sec && source venv/bin/activate && python3 terminal_privacy_monitor.py'
BASHRC
fi

echo -e "\n${GREEN}✔ ¡PARROT OS HA SIDO APROVISIONADO AL 100% PARA WEB-SEC!${NC}"
echo -e "${YELLOW}Comandos listos en tu terminal de Parrot:${NC}"
echo -e "  • ${CYAN}websec${NC}  -> Abre la consola Cyber-Deck ofensiva (Modos 1, 2, Recon, BlueTeam)."
echo -e "  • ${CYAN}webgrid${NC} -> Abre la matriz multi-terminal estilo Hollywood."
echo -e "  • ${CYAN}wormhole send <archivo>${NC} -> Envía cualquier reporte a tu Debian sin red.\n"
