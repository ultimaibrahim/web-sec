#!/bin/bash
# launch_dual_arena.sh - Lanza simultáneamente la TUI Red Team y la TUI Blue Team en ventanas independientes.

xterm -geometry 105x32+50+50 -title "⚡ ULTIMA WEB SEC // BLUE TEAM SOC" -e "python3 /home/ultimau/web_sec_fork/mode3_blueteam.py" &
BLUE_PID=$!

sleep 1

xterm -geometry 115x35+750+50 -title "⚡ ULTIMA WEB SEC // RED TEAM CYBER-DECK" -e "python3 /home/ultimau/web_sec_fork/mode2_richlive.py" &
RED_PID=$!

echo "Dual Arena iniciada:"
echo " - Blue Team SOC PID: $BLUE_PID"
echo " - Red Team Deck PID: $RED_PID"
