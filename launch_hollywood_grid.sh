#!/usr/bin/env bash
# launch_hollywood_grid.sh - Orquestador multi-terminal estilo Hollywood Cyberdeck
# Lanza los 4 frentes especializados del sistema en ventanas Alacritty flotantes y sincronizadas.
# CERO ELEMENTOS DUPLICADOS:
# 1. 🛡️ Blue Team SOC: Honeypots, Trampas Canario, Ban-list y Tarpit.
# 2. ⚡ Red Team Deck: Motor ofensivo, Inyección de Plugins y Consola Interactiva.
# 3. 🔒 Privacy Guard: Telemetría de Kernel, Fugas WAN, DNS y Kill-Switch.
# 4. 🔑 Cred Vault: Visor en vivo de base de datos SQLite y Tokens extraídos.

set -e

REPO_DIR="/home/ultimau/web_sec_fork"
TERM_BIN="alacritty"

if ! command -v "$TERM_BIN" >/dev/null 2>&1; then
    TERM_BIN="xterm"
fi

echo "⚡ Desplegando Grid Hollywood Multi-Terminal ($TERM_BIN)..."

# 1. Blue Team SOC (Ventana Superior Izquierda)
$TERM_BIN -T "🛡️ BLUE TEAM // SOC & ACTIVE DEFENSE" \
    --hold \
    -e bash -c "python3 $REPO_DIR/mode3_blueteam.py" &
PID_BLUE=$!

sleep 0.35

# 2. Red Team Cyber-Deck Central (Ventana Principal)
$TERM_BIN -T "⚡ RED TEAM // OFFENSIVE CYBER-DECK" \
    --hold \
    -e bash -c "python3 $REPO_DIR/mode2_richlive.py 1" &
PID_RED=$!

sleep 0.35

# 3. Privacy Guard Telemetry Monitor (Ventana de Red y Escudos)
$TERM_BIN -T "🔒 ZERO-LEAK // PRIVACY TELEMETRY" \
    --hold \
    -e bash -c "python3 $REPO_DIR/terminal_privacy_monitor.py" &
PID_PRIV=$!

sleep 0.35

# 4. Credential Vault & Findings Live Ticker (Ventana de Base de Datos y Evidencias)
$TERM_BIN -T "🔑 CRED VAULT // ENCRYPTED STORAGE" \
    --hold \
    -e bash -c "python3 $REPO_DIR/terminal_vault_ticker.py" &
PID_VAULT=$!

echo -e "\n✔ Los 4 Frentes de la Grid Hollywood han sido desplegados:"
echo "  [1] 🛡️ Blue Team SOC    (PID: $PID_BLUE)"
echo "  [2] ⚡ Red Team Deck    (PID: $PID_RED)"
echo "  [3] 🔒 Privacy Telemetry (PID: $PID_PRIV)"
echo "  [4] 🔑 Cred Vault Live   (PID: $PID_VAULT)"
