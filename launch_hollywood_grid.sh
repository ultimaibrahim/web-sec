#!/usr/bin/env bash
# launch_hollywood_grid.sh - Orquestador multi-terminal estilo Hollywood Cyberdeck
# Lanza los frentes del sistema en ventanas Alacritty / i3 flotantes e independientes.

set -e

REPO_DIR="/home/ultimau/web_sec_fork"
TERM_BIN="alacritty"

if ! command -v "$TERM_BIN" >/dev/null 2>&1; then
    TERM_BIN="xterm"
fi

echo "⚡ Iniciando Suite Web-Sec en modo Hollywood Multi-Terminal ($TERM_BIN)..."

# 1. Terminal 1: Blue Team SOC (Defensa Activa, Tarpit y Alertas)
$TERM_BIN -T "🛡️ BLUE TEAM SOC // DEFENSE & TARPIT" -e bash -c "python3 $REPO_DIR/mode3_blueteam.py" &
PID_BLUE=$!

sleep 0.4

# 2. Terminal 2: Cyber-Deck Central (Stream, Engine & Scanner)
$TERM_BIN -T "⚡ RED TEAM // OFFENSIVE CYBER-DECK" -e bash -c "python3 $REPO_DIR/mode2_richlive.py 1" &
PID_RED=$!

sleep 0.4

# 3. Terminal 3: Privacy Guard Live Monitor (Auditoría continua de WAN, DNS, Tor y VPN)
$TERM_BIN -T "🔒 PRIVACY GUARD // ZERO-LEAK TELEMETRY" -e bash -c "watch -n 2 python3 $REPO_DIR/privacy_guard.py" &
PID_PRIV=$!

sleep 0.4

# 4. Terminal 4: Credential Vault & Findings Live Ticker
$TERM_BIN -T "🔑 VAULT EXPLORER // REAL-TIME HIT TICKER" -e bash -c "python3 -c '
import time
from rich.console import Console
from rich.table import Table
import storage_vault

console = Console()
console.print(\"[bold cyan]Observando Credential Vault SQLite en vivo...[/]\")
last_count = -1
while True:
    try:
        findings = storage_vault.list_findings(limit=15)
        if len(findings) != last_count:
            console.clear()
            table = Table(title=\"🔥 ÚLTIMAS EVIDENCIAS Y TOKENS CAPTURADOS\", border_style=\"yellow\")
            table.add_column(\"ID\", style=\"dim\")
            table.add_column(\"Target\", style=\"white\")
            table.add_column(\"Plugin\", style=\"cyan\")
            table.add_column(\"Key\", style=\"yellow\")
            table.add_column(\"Value\", style=\"green\")
            table.add_column(\"Date\", style=\"dim\")
            for f in findings:
                table.add_row(str(f[\"id\"]), f[\"target\"], f[\"plugin\"], f[\"finding_type\"], str(f[\"value\"])[:35], f[\"created_at\"][11:19])
            console.print(table)
            last_count = len(findings)
    except Exception as e:
        pass
    time.sleep(2)
'" &
PID_VAULT=$!

echo -e "\n✔ 4 Terminales operativas lanzadas exitosamente:"
echo "  [1] Blue Team SOC PID: $PID_BLUE"
echo "  [2] Red Team Deck PID: $PID_RED"
echo "  [3] Privacy Telemetry PID: $PID_PRIV"
echo "  [4] Cred Vault PID: $PID_VAULT"
