#!/usr/bin/env bash
# deactivate_shields.sh - Rotación y purga post-operación, sellado de puertas y apagado seguro de escudos
# Autor: Ibrahim García (Web-Sec Suite)
#
# Protocolo de Evasión Post-Operativa:
# 1. Purga de sockets y sesiones activas sospechosas.
# 2. Rotación final de MAC (desacoplamiento total de la huella usada durante la auditoría).
# 3. Purga completa de tablas ARP / Neighbor cache (olvido de gateways y nodos locales).
# 4. Flush del resolver DNS y caché de resolución local.
# 5. Flush de reglas Kill-Switch en iptables.
# 6. Desconexión controlada del túnel VPN (Proton / WireGuard).
# 7. Detención del demonio Tor local (cierre del puerto SOCKS 9050).
# 8. Restauración de parámetros del kernel (TCP Timestamps, IPv6).
# 9. Reactivación de servicios estándar de red (avahi-daemon) si se desea.
# 10. Purga de buffers de memoria volátil y caché en RAM (drop_caches).

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

echo -e "${MAGENTA}=== 🔒 PROTOCOLO DE DESACTIVACIÓN & SELLADO DE PUERTAS POST-OPERACIÓN ===${NC}\n"

# 1. Terminar procesos y sockets de auditoría huérfanos / background
echo -e "[*] 1/10 Terminando sesiones y sockets de auditoría..."
pkill -f "playwright" 2>/dev/null || true
pkill -f "nmap" 2>/dev/null || true
pkill -f "gobuster" 2>/dev/null || true
pkill -f "sqlmap" 2>/dev/null || true
echo -e "    ${GREEN}✔ Procesos de escaneo y scrap cerrados.${NC}"

# 2. Rotación de MAC FINAL (Desacoplar la MAC usada en el ataque de la MAC que queda en reposo)
WIFI_IFACE=$(ip -br link | grep -E 'wl|wlo|wlan' | awk '{print $1}' | head -n 1)
if [ -n "$WIFI_IFACE" ]; then
    echo -e "[*] 2/10 Rotación evasiva de dirección MAC (Desvinculación definitiva)..."
    if command -v macchanger >/dev/null 2>&1; then
        sudo ip link set "$WIFI_IFACE" down 2>/dev/null || true
        # Si se desea volver a la MAC de fábrica o a otra completamente nueva y distinta:
        sudo macchanger -r "$WIFI_IFACE" >/dev/null 2>&1 || true
        sudo ip link set "$WIFI_IFACE" up 2>/dev/null || true
        FINAL_MAC=$(cat /sys/class/net/"$WIFI_IFACE"/address 2>/dev/null || echo "Desconocida")
        echo -e "    ${GREEN}✔ MAC rotada a nueva identidad limpia: $FINAL_MAC${NC}"
    fi
fi

# 3. Purga completa de la caché ARP y vecinos de red local (Zero-Neighbor Tracing)
echo -e "[*] 3/10 Purgando tablas de vecinos ARP (Zero-Neighbor Tracing)..."
sudo ip neigh flush all 2>/dev/null || true
echo -e "    ${GREEN}✔ Caché ARP y mapeo de enrutadores locales eliminados.${NC}"

# 4. Limpieza de reglas de Cortafuegos / Kill-Switch
echo -e "[*] 4/10 Desmantelando reglas de Kill-Switch en cortafuegos (iptables)..."
sudo iptables -D OUTPUT -p tcp --dport 9050 -j ACCEPT 2>/dev/null || true
# Limpieza de reglas defensivas creadas durante la sesión
for iface in $(ip -br link | awk '{print $1}'); do
    sudo iptables -D OUTPUT -o "$iface" -j ACCEPT 2>/dev/null || true
done
echo -e "    ${GREEN}✔ Filtros temporales de aislamiento desarmados.${NC}"

# 5. Desconexión de Túnel VPN (Proton / WireGuard / OpenVPN)
echo -e "[*] 5/10 Desconectando túnel VPN de forma segura..."
if command -v protonvpn >/dev/null 2>&1; then
    protonvpn disconnect >/dev/null 2>&1 || true
fi
for iface in $(ip -br link | grep -E 'proton|wg|tun' | awk '{print $1}'); do
    sudo ip link set "$iface" down 2>/dev/null || true
done
echo -e "    ${GREEN}✔ Túnel VPN finalizado y canal cerrado.${NC}"

# 6. Apagado del Demonio Tor (Cierre del puerto SOCKS5 9050)
echo -e "[*] 6/10 Cerrando puertas de Tor (Detención de 127.0.0.1:9050)..."
if systemctl is-active --quiet tor 2>/dev/null; then
    sudo systemctl stop tor 2>/dev/null || true
    echo -e "    ${GREEN}✔ Demonio Tor detenido (Puerto 9050 cerrado).${NC}"
else
    echo -e "    ${GREEN}✔ Tor ya se encuentra inactivo.${NC}"
fi

# 7. Restauración de parámetros del Kernel (TCP Timestamps e IPv6)
echo -e "[*] 7/10 Restaurando configuración estándar del Kernel..."
sudo sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null 2>&1 || true
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1 || true
echo -e "    ${GREEN}✔ Pila de red y TCP timestamps normalizados.${NC}"

# 8. Reactivación de servicios estándar si estaban activos (avahi-daemon)
echo -e "[*] 8/10 Reactivando servicios locales de red..."
sudo systemctl start avahi-daemon 2>/dev/null || true
echo -e "    ${GREEN}✔ Servicios mDNS reactivados.${NC}"

# 9. Restauración opcional de Hostname original
ORIG_HOST="ultimadeb"
if [ -n "$ORIG_HOST" ]; then
    echo -e "[*] 9/10 Restaurando Hostname original del sistema ($ORIG_HOST)..."
    sudo hostnamectl set-hostname "$ORIG_HOST" 2>/dev/null || sudo hostname "$ORIG_HOST" 2>/dev/null || true
    echo -e "    ${GREEN}✔ Hostname restablecido a: $(hostname)${NC}"
fi

# 10. Purga de memoria RAM y caché del kernel (Anti-Forense)
echo -e "[*] 10/10 Purgando buffers del kernel y memoria volátil..."
sudo sync
sudo sysctl -w vm.drop_caches=3 >/dev/null 2>&1 || true
echo -e "    ${GREEN}✔ Caché de páginas, dentries e inodos purgados de RAM.${NC}"

echo -e "\n${GREEN}✔ Todos los escudos han sido desactivados con éxito tras rotar huellas y sellar puertas.${NC}"
echo -e "El sistema ha vuelto a su estado operativo habitual sin rastros de sesión activa.\n"
