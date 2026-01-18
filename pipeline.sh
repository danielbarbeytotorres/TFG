#!/usr/bin/env bash
set -euo pipefail

START_TIME=$(date +%s)

# ==== CONFIGURACIÓN ====
FORMAT_ID="5057e5cc-b825-11e4-9d0e-28d24461215b"
BASE_DIR="/home/kali/TFG/reports"
VENV="/home/kali/TFG/tools/venv_openai/bin/activate"

# SSH / SCP
SSH_KEY_PATH="${SSH_KEY_PATH:-/home/kali/.ssh/id_ed25519_centinela}"
SSH_USER="${SSH_USER:-centinela}"
SSH_DEST_DIR="${SSH_DEST_DIR:-/tmp}"
SSH_PORT="${SSH_PORT:-}"
SSH_STRICT="${SSH_STRICT:-no}"

# ==== DIRECTORIOS ====
DATE_TAG=$(date +%F)
REPORT_DIR="$BASE_DIR/$DATE_TAG"
mkdir -p "$REPORT_DIR"

# =========================================================
#  FASE 1: FORMATEO Y CREACIÓN DE SCRIPTS
# =========================================================
clear

gum style \
    --border double \
    --margin "1 1" \
    --padding "1 4" \
    --border-foreground 33 \
    --foreground 33 \
    --bold \
    "   PROCESADO DIARIO DE VULNERABILIDADES   "

gum join --horizontal \
    "$(gum style --foreground 33 '📅 FECHA DE EJECUCIÓN: ')" \
    "$(gum style --foreground 255 "$DATE_TAG")"

gum join --horizontal \
    "$(gum style --foreground 33 '📂 DIRECTORIO BASE:   ')" \
    "$(gum style --foreground 255 "$REPORT_DIR")"

TASK_IDS=$(gvm-cli --gmp-username USUARIO_GVM --gmp-password CONTRASENA_GVM socket --xml "<get_tasks/>" 2>/dev/null | grep -oP '(?<=task id=")[^"]+')

if [ -z "$TASK_IDS" ]; then
    echo "No hay tasks configuradas. Procesamiento completado."
    exit 0
fi

echo "$TASK_IDS" | while read TASK_ID; do

    TASK_DIR="$REPORT_DIR/$TASK_ID"
    mkdir -p "$TASK_DIR"

    XML_FILE="$TASK_DIR/report.xml"
    JSON_FILE="$TASK_DIR/report.json"
    SPLIT_DIR="$TASK_DIR/split"
    SCRIPTS_DIR="$TASK_DIR/scripts"
    LOGS_DIR="$REPORT_DIR/logs"

    gum style \
    --border rounded \
    --margin "1 0" \
    --padding "0 2" \
    --border-foreground 33 \
    --foreground 33 \
    --bold \
    "Procesando la Task ID: ${TASK_ID}"

    REPORT_ID=$(gvm-cli --gmp-username USUARIO_GVM --gmp-password CONTRASENA_GVM socket --xml "<get_tasks task_id=\"${TASK_ID}\" details='1'/>" | grep -oP '(?<=<report id=\")[^\"]+' || true)


    if [ -z "$REPORT_ID" ]; then
        echo "❌ No hay reports realizados para la task ${TASK_ID}. Procesamiento completado."
    else

        # ==== 1. OBTENER ÚLTIMO REPORT ID ====
        TEMP_ID_FILE=$(mktemp)
        gum spin --spinner dot --title "Buscando último report de la task..." -- \
            bash -c "gvm-cli --gmp-username USUARIO_GVM --gmp-password CONTRASENA_GVM socket --xml \"<get_tasks task_id='$TASK_ID' details='1'/>\" | grep -oP '(?<=<report id=\")[^\"]+' | tail -1 > $TEMP_ID_FILE"

        LAST_REPORT_ID=$(cat "$TEMP_ID_FILE")
        rm "$TEMP_ID_FILE"

        if [ -z "$LAST_REPORT_ID" ]; then
            gum style --foreground 196 --bold "✘ [ERROR] No se encontró ningún report para la task $TASK_ID"
            exit 1
        fi
        gum style --foreground 82 "✔ Obtenido último report ID con éxito: $LAST_REPORT_ID"
        echo ""

        # ==== 2. DESCARGAR REPORTE EN XML ====
        if gum spin --spinner dot --title "Descargando reporte en formato XML..." -- \
            bash -c "gvm-cli --gmp-username USUARIO_GVM --gmp-password CONTRASENA_GVM socket --xml \"<get_reports report_id='$LAST_REPORT_ID' format_id='$FORMAT_ID' details='1' filter='apply_overrides=0 levels=hmlg rows=100 min_qod=70 first=1 sort-reverse=severity'/>\" > \"$XML_FILE\""; then
            gum style --foreground 82 "✔ Reporte guardado con éxito: $XML_FILE"
        else
            gum style --foreground 196 --bold "✘ Falló la descarga o decodificación del reporte."
            exit 1
        fi
        echo ""
        
        # ==== 3. PARSEAR A JSON ====
        if [ ! -x "/home/kali/TFG/tools/parseador.py" ]; then
            gum style --foreground 196 --bold "✘ No se encontró parseador.py o no tiene permisos."
            exit 1
        fi

        if gum spin --spinner minidot --title "Parseando XML a JSON..." -- \
            python3 /home/kali/TFG/tools/parseador.py "$XML_FILE" "$JSON_FILE"; then
            gum style --foreground 82 "✔ JSON generado con éxito: $JSON_FILE"
        else
            gum style --foreground 196 --bold "✘ Error durante el parseo del archivo."
            exit 1
        fi
        echo ""

        # ==== 4. DIVIDIR JSON EN VULNERABILIDADES ====
        if [ ! -x "/home/kali/TFG/tools/spliteador.py" ]; then
            gum style --foreground 196 --bold "✘ No se encontró spliteador.py."
            exit 1
        fi

        if gum spin --spinner points --title "Dividiendo JSON en vulnerabilidades..." -- \
            bash -c "mkdir -p \"$SPLIT_DIR\" && python3 /home/kali/TFG/tools/spliteador.py \"$JSON_FILE\" \"$SPLIT_DIR\""; then
            gum style --foreground 82 "✔ JSON dividido en vulnerabilidades con éxito: $SPLIT_DIR"
        else
            gum style --foreground 196 --bold "✘ Falló la división del archivo JSON."
            exit 1
        fi
        echo ""

        # ==== 5. GENERACIÓN DE SCRIPT DE SEGURIDAD ====

        gum style \
            --border normal \
            --margin "1" \
            --padding "0 1" \
            --border-foreground 33 \
            --foreground 33 \
            "GENERACIÓN DE SCRIPTS DE SEGURIDAD"

        gum style --foreground 255 "  📂 Directorio de vulnerabilidades: $SPLIT_DIR"
        gum style --foreground 255 "  📂 Directorio destino: $SCRIPTS_DIR"
        echo ""

        if [ ! -f "/home/kali/TFG/tools/agent.py" ]; then
            gum style --foreground 196 --bold "✘ No se encontró agent.py"
        else
            mkdir -p "$SCRIPTS_DIR"

            if [ -f "$VENV" ]; then
                source "$VENV"
                gum style --foreground 82 "✔ Entorno virtual activado."
            else
                gum style --foreground 196 --bold "✘ No se encontró el virtualenv en: $VENV"
            fi
            echo ""

            python3 /home/kali/TFG/tools/agent.py "$SPLIT_DIR" "$SCRIPTS_DIR"
            PYTHON_EXIT_CODE=$?

            echo ""

            if [ $PYTHON_EXIT_CODE -eq 0 ]; then
                gum style --foreground 82 "✔ agent.py finalizó correctamente."
            else
                gum style --foreground 196 --bold "✘ agent.py falló al generar los scripts."
            fi
            
            deactivate 2>/dev/null || true
            echo ""

            NUM_GENERADOS=$(find "$SCRIPTS_DIR" -type f -name '*.sh' 2>/dev/null | wc -l)

            if [ "$NUM_GENERADOS" -gt 0 ]; then
                gum style --foreground 82 --bold "✔ ÉXITO: Se generaron $NUM_GENERADOS scripts en total en: $SCRIPTS_DIR"
            else
                gum style --foreground 196 --bold "⚠ ALERTA: No se generó ningún script."
            fi
        fi
        echo ""

        # =========================================================
        #  FASE 2: DESPLIEGUE Y EJECUCIÓN
        # =========================================================

        gum style \
            --border normal \
            --margin "1" \
            --padding "0 1" \
            --border-foreground 33 \
            --foreground 33 \
            "DESPLIEGUE Y EJECUCIÓN REMOTA"

        TARGET_ID=$(gvm-cli --gmp-username USUARIO_GVM --gmp-password CONTRASENA_GVM socket --xml "<get_tasks task_id=\"$TASK_ID\" details='1'/>" | grep -oP '(?<=<target id=\")[^\"]+')
        SSH_HOST=$(gvm-cli --gmp-username USUARIO_GVM --gmp-password CONTRASENA_GVM socket --xml "<get_targets target_id=\"$TARGET_ID\"/>" | grep -oP '(?<=<hosts>)[^<]+')

        # === RECOGER LISTA DE SCRIPTS (local) ===
        declare -a FULL_FILES=()
        declare -a BASE_FILES=()
        while IFS= read -r -d '' f; do
          FULL_FILES+=("$f")
          BASE_FILES+=("$(basename "$f")")
        done < <(find "$SCRIPTS_DIR" -type f -name '*.sh' -print0)

        shopt -s nullglob
        SCP_PORT_OPTS=()
        SSH_PORT_OPT=()
        if [ -n "$SSH_PORT" ]; then
          SCP_PORT_OPTS=(-P "$SSH_PORT")
          SSH_PORT_OPT=(-p "$SSH_PORT")
        fi

        if [ ${#FULL_FILES[@]} -eq 0 ]; then
            gum style --foreground 196 "⚠ No hay scripts para transferir. Saltando ejecución remota."
        else

        # === ENVIAR SCRIPTS VIA SCP A /tmp ===
            if gum spin --spinner globe --title "Enviando ${#FULL_FILES[@]} scripts a ${SSH_HOST}..." -- \
                scp "${SCP_PORT_OPTS[@]}" -i "$SSH_KEY_PATH" -o StrictHostKeyChecking="$SSH_STRICT" \
                "${FULL_FILES[@]}" "$SSH_USER"@"$SSH_HOST":"$SSH_DEST_DIR"/; then
                gum style --foreground 82 "✔ Transferencia SCP completada correctamente."
            else
                gum style --foreground 196 --bold "✘ Error al transferir archivos por SCP."
            fi
        fi

        echo ""

        gum style --foreground 255 "📂 Guardando logs locales en: $LOGS_DIR"
        mkdir -p "$LOGS_DIR"
        echo ""

        OK_COUNT=0
        FAIL_COUNT=0

        gum style --foreground 240 -- "---------------------------------------------------"

        for base in "${BASE_FILES[@]}"; do
          remote_path="$SSH_DEST_DIR/$base"
          local_log="$LOGS_DIR/${base%.sh}.log"

          if gum spin --spinner dot --title "Ejecutando $base..." -- \
             bash -c "ssh -n ${SSH_PORT_OPT[@]} -i '$SSH_KEY_PATH' -o StrictHostKeyChecking='$SSH_STRICT' '$SSH_USER'@'$SSH_HOST' \
                \"chmod +x '$remote_path' 2>/dev/null || true; sudo /bin/bash '$remote_path'\" >'$local_log' 2>&1"; then

             printf "\n==== RESULT ====\nExitCode: 0\nTimestamp: %s\n" "$(date +'%F_%T')" >> "$local_log"
             gum style --foreground 82 "  ✔ $base (OK)"
             OK_COUNT=$((OK_COUNT+1))
          else
             rc=$?
             printf "\n==== RESULT ====\nExitCode: %d\nTimestamp: %s\n" "$rc" "$(date +'%F_%T')" >> "$local_log"
             gum style --foreground 196 "  ✘ $base (Exit Code: $rc)"
             FAIL_COUNT=$((FAIL_COUNT+1))
          fi

          ssh -n "${SSH_PORT_OPT[@]}" -i "$SSH_KEY_PATH" -o StrictHostKeyChecking="$SSH_STRICT" "$SSH_USER"@"$SSH_HOST" \
              "rm -f '$remote_path' 2>/dev/null || true"
        done

        gum style --foreground 240 -- "---------------------------------------------------"
        echo ""

        ## ==== RESUMEN FINAL ====

        SUMMARY_HOST="${SSH_HOST:-N/A}"
        
        SUMMARY_DATA="MÉTRICA,VALOR
            📅 Fecha,$DATE_TAG
            🆔 Task ID,$TASK_ID
            🎯 IP Objetivo,$SUMMARY_HOST
            📄 Report ID,$LAST_REPORT_ID
            🤖 Scripts Generados,$NUM_GENERADOS
            ✅ Ejecutados OK,${OK_COUNT:-0}
            ❌ Ejecutados FAIL,${FAIL_COUNT:-0}
            📂 Dir. Logs,$LOGS_DIR"

        echo "$SUMMARY_DATA" | gum table \
            --print \
            --border double \
            --border.foreground 33 \
            --widths 25,80 \
            --separator ","

        echo ""

    fi
    sleep 1
done
# Fin del bucle

deactivate 2>/dev/null || true

# === CÁLCULO DE TIEMPO TOTAL ===
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

H=$((ELAPSED / 3600))
M=$(( (ELAPSED % 3600) / 60 ))
S=$((ELAPSED % 60))
TIME_STR=$(printf "%02dh %02dm %02ds" $H $M $S)

echo ""
echo ""

gum style \
    --border rounded \
    --border-foreground 33 \
    --margin "0 1" \
    --padding "0 2" \
    --foreground 33 \
    --bold \
    "TIEMPO TOTAL DE EJECUCIÓN: $TIME_STR"
