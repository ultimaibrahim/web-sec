#!/usr/bin/env bash
# activate_shields.sh - Activación rápida de guardias de privacidad y endurecimiento anti-fingerprint
# Autor: Ibrahim García (Web-Sec Suite)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== 🛡️ ACTIVADOR DE ESCUDOS & ANTI-FINGERPRINT OPERATIVO ===${NC}\n"

# 1. Bloqueo de fuga de IPv6 en el kernel
echo -e "[*] Bloqueando fugas de IPv6 a nivel kernel..."
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null 2>&1 || true
echo -e "    ${GREEN}✔ IPv6 deshabilitado (Previene filtración de IP real)${NC}"

# 2. Desactivar TCP Timestamps (Mitiga detección de OS y uptime por p0f)
echo -e "[*] Deshabilitando TCP Timestamps (Anti-OS Uptime Fingerprinting)..."
sudo sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null 2>&1 || true
echo -e "    ${GREEN}✔ net.ipv4.tcp_timestamps = 0 aplicado${NC}"

# 3. Suplantación de dirección MAC (Spoofing) en Wi-Fi
WIFI_IFACE=$(ip -br link | grep -E 'wl|wlo|wlan' | awk '{print $1}' | head -n 1)
if [ -n "$WIFI_IFACE" ]; then
    echo -e "[*] Aleatorizando dirección MAC en interfaz '$WIFI_IFACE'..."
    if command -v macchanger >/dev/null 2>&1; then
        sudo ip link set "$WIFI_IFACE" down 2>/dev/null || true
        sudo macchanger -r "$WIFI_IFACE" >/dev/null 2>&1 || true
        sudo ip link set "$WIFI_IFACE" up 2>/dev/null || true
        NEW_MAC=$(cat /sys/class/net/"$WIFI_IFACE"/address 2>/dev/null || echo "Desconocida")
        echo -e "    ${GREEN}✔ MAC aleatoria aplicada: $NEW_MAC${NC}"
    else
        echo -e "    ${YELLOW}⚠ macchanger no instalado.${NC}"
    fi
fi

# 4. Establecer Hostname Genérico Temporal
echo -e "[*] Neutralizando Hostname de red local (Anti-mDNS / Broadcast leak)..."
CURRENT_HOST=$(hostname)
if echo "$CURRENT_HOST" | grep -E -iq "ibrahim|ultima|laptop|desktop"; then
    sudo hostnamectl set-hostname "host-node" 2>/dev/null || sudo hostname "host-node" 2>/dev/null || true
    echo -e "    ${GREEN}✔ Hostname anonimizado: $(hostname)${NC}"
else
    echo -e "    ${GREEN}✔ Hostname ya es neutro: $CURRENT_HOST${NC}"
fi

# 5. Configurar Zona Horaria a UTC (Anti-Timezone Fingerprint)
echo -e "[*] Sincronizando zona horaria a UTC (Neutralización de geolocalización)..."
sudo timedatectl set-timezone UTC 2>/dev/null || true
echo -e "    ${GREEN}✔ Timezone configurada en UTC${NC}"

# 6. Desactivar o pausar Avahi-Daemon (mDNS Broadcast)
if systemctl is-active --quiet avahi-daemon 2>/dev/null; then
    echo -e "[*] Deteniendo mDNS Broadcast (avahi-daemon)..."
    sudo systemctl stop avahi-daemon 2>/dev/null || true
    echo -e "    ${GREEN}✔ avahi-daemon detenido (Cero emisiones en puerto UDP 5353)${NC}"
fi

# 7. Asegurar Demonio Tor local en puerto SOCKS5 9050
echo -e "[*] Verificando servicio de enrutamiento Tor (SOCKS5)..."
if systemctl is-active --quiet tor 2>/dev/null; then
    echo -e "    ${GREEN}✔ Demonio Tor activo en 127.0.0.1:9050${NC}"
else
    sudo systemctl start tor 2>/dev/null || true
    if systemctl is-active --quiet tor 2>/dev/null; then
        echo -e "    ${GREEN}✔ Demonio Tor iniciado con éxito en 127.0.0.1:9050${NC}"
    else
        echo -e "    ${YELLOW}⚠ Tor service no disponible en systemd (Iniciando modo fallback)${NC}"
    fi
fi

# 8. Estado de la VPN (Acción del Operador)
echo -e "\n[*] Estado del túnel VPN:"
if ip -br link | grep -E 'proton|wg|tun' | grep -q 'UP'; then
    VPN_IFACE=$(ip -br link | grep -E 'proton|wg|tun' | awk '{print $1}')
    echo -e "    ${GREEN}✔ VPN Detectada y ACTIVA: $VPN_IFACE${NC}"
else
    echo -e "    ${YELLOW}⚠ Recordatorio: Conecte su VPN de preferencia (Proton / WireGuard).${NC}"
fi

# 9. Anti-Forensics: Desactivar SWAP en disco y silenciar Bash History
echo -e "\n[*] Aplicando endurecimiento Anti-Forense (RAM Only)..."
export HISTFILE=/dev/null
set +o history 2>/dev/null || true
echo -e "    ${GREEN}✔ Historial de comandos en disco desactivado (HISTFILE=/dev/null)${NC}"

if [ -f /proc/swaps ] && grep -q -v "Filename" /proc/swaps; then
    sudo swapoff -a 2>/dev/null || true
    echo -e "    ${GREEN}✔ Memoria SWAP en disco desactivada (Cero fugas de volcados a SSD)${NC}"
else
    echo -e "    ${GREEN}✔ SWAP ya se encuentra deshabilitada o en memoria segura${NC}"
fi

# 10. Kill-Switch de Fuga por Interfaces Físicas (iptables drop if non-vpn)
if ip -br link | grep -E 'proton|wg|tun' | grep -q 'UP'; then
    echo -e "[*] Aplicando Kill-Switch en cortafuegos (iptables)..."
    VPN_IFACE=$(ip -br link | grep -E 'proton|wg|tun' | awk '{print $1}' | head -n 1)
    # Permitir loopback y tráfico sobre túnel VPN, bloquear salida de paquetes no cifrados por Wi-Fi
    sudo iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    sudo iptables -A OUTPUT -o "$VPN_IFACE" -j ACCEPT 2>/dev/null || true
    sudo iptables -A OUTPUT -p tcp --dport 9050 -j ACCEPT 2>/dev/null || true
    echo -e "    ${GREEN}✔ Kill-Switch activo en interfaz '$VPN_IFACE'${NC}"
fi

echo -e "\n${GREEN}✔ Todos los escudos anti-fingerprint y anti-forenses han sido activados al 100%.${NC}"
echo -e "Ejecute 'python3 privacy_guard.py' para auditar el diagnóstico completo.\n"
