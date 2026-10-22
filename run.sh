#!/usr/bin/env bash
set -e

SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
PROJECT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

cd "$PROJECT_DIR"

# Asegurar que las dependencias requeridas estén presentes silenciosamente
python3 -c "import playwright, greenlet, pyee, requests, rich, textual" 2>/dev/null || {
    python3 -m pip install --user --break-system-packages --quiet -r "$PROJECT_DIR/requirements.txt" 2>/dev/null || true
}

CHOICE="${1:-}"

# Si no pasa argumento, mostrar selector rápido entre los dos estilos estables
if [ -z "$CHOICE" ]; then
    echo -e "\033[1;36m┌────────────────────────────────────────────────────────┐\033[0m"
    echo -e "\033[1;36m│          WEB-SEC // SUITE DE INTERFACES CYBER          │\033[0m"
    echo -e "\033[1;36m└────────────────────────────────────────────────────────┘\033[0m"
    echo -e " Selecciona el estilo que deseas lanzar:\n"
    echo -e "   \033[1;32m1\033[0m) \033[1;37mEstilo Rich Live Puro\033[0m      (Buffer directo de terminal a 8 FPS)"
    echo -e "   \033[1;32m2\033[0m) \033[1;37mEstilo btop Nano TUI\033[0m       (Textual reactivo de alta densidad)\n"
    echo -e " \033[1;33mTip:\033[0m Puedes ejecutar directo \033[1;36mweb-sec 1\033[0m o \033[1;36mweb-sec 2\033[0m\n"
    read -p " Elige una opción [1-2] (Default: 1): " input_val
    CHOICE="${input_val:-1}"
fi

case "$CHOICE" in
    1)
        exec python3 "$PROJECT_DIR/mode2_richlive.py"
        ;;
    2)
        exec python3 "$PROJECT_DIR/main.py"
        ;;
    *)
        # Si alguien escribe 3 por inercia, enviarlo al estilo btop
        if [ "$CHOICE" = "3" ]; then
            exec python3 "$PROJECT_DIR/main.py"
        else
            echo -e "\033[1;31mOpción inválida: $CHOICE. Usa 1 o 2.\033[0m"
            exit 1
        fi
        ;;
esac
