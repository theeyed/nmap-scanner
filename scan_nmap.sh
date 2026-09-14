#!/bin/bash
#===============================================================================
# scan_nmap.sh - Escaneo avanzado de puertos con Nmap
# Uso únicamente en sistemas y redes en los que se tiene autorización expresa.
# El autor no se hace responsable del mal uso de esta herramienta.
#===============================================================================

set -euo pipefail

#------------------------------------------------------------------------------ config
VERSION="1.0.0"
DEFAULT_PORTS="1-1000"
DEFAULT_TIMING=4
DEFAULT_PROFILE="basic"
OUTPUT_DIR_ARG=""
VERBOSE=false
CONFIRM_YES=false
LOGFILE=""
EXIT_OK=0
EXIT_VALIDATION=1
EXIT_PERMISSION=2
EXIT_NMAP=3
SCRIPT_DATE=""
STAMP=""

#------------------------------------------------------------------------------ helpers
usage() {
    cat <<'EOF'
scan_nmap.sh - Escaneo de puertos con Nmap (especialista en ciberseguridad)

USO:
  scan_nmap.sh -t <objetivo> [opciones]

OPCIONES OBLIGATORIAS:
  -t <objetivo>        IP, rango CIDR o múltiples separados por comas.
                       Ej: 8.8.8.8 | 192.168.1.0/24 | 10.0.0.1,10.0.0.2

OPCIONES OPCIONALES:
  -p <puertos>         Puertos o rangos. Default: 1-1000. Ej: 22,80,443 | 1-65535
  -m <perfil>          Perfil de escaneo. Default: basic.
                       basic  -> -sT connect (sin root)
                       service-> -sV detección de versiones
                       os     -> -O -sS detección de SO (requiere root)
                       full   -> -A -sS -O agresivo (requiere root)
                       udp    -> -sU top 200 puertos UDP (requiere root)
  -T <0-5>             Plantilla de tiempos. Default: 4
  -x <excluir>         IPs/rangos a excluir (usa --exclude).
  -o <dir>             Directorio de salida. Default: ./informes
  -y                   Omitir confirmación (modo no interactivo / CI).
  -v                   Verboso (pasa -v a Nmap).
  -h                   Muestra esta ayuda.

EXIT CODES:
  0 Ok  1 Error de validación  2 Permisos insuficientes  3 Nmap falló

EJEMPLOS:
  scan_nmap.sh -t 192.168.1.10
  scan_nmap.sh -t 192.168.1.10 -m service -p 22,80,443,8080
  scan_nmap.sh -t 10.0.0.0/24 -m os -o ./escaneos -x 10.0.0.1
  scan_nmap.sh -t 8.8.8.8 -m full -T 3 -v
EOF
    exit "$EXIT_OK"
}

log() {
    local level="$1"; shift
    if [[ -n "$LOGFILE" ]]; then
        printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" >>"$LOGFILE"
    fi
    if [[ "$level" == "ERROR" ]]; then
        printf '[%s] %s\n' "$level" "$*" >&2
    elif [[ "$level" == "OK" && "$VERBOSE" == "true" ]]; then
        printf '%s\n' "$*"
    fi
}

die() {
    log "ERROR" "$*"
    exit "$EXIT_VALIDATION"
}

sane_name() {
    local name="$1"
    name="${name//\//_}"
    name="${name//,/_}"
    printf '%s' "$name"
}

#------------------------------------------------------------------------------ validaciones
re_ip4='^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$'
re_cidr='^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/([0-9]|[12][0-9]|3[0-2])$'
re_ports='^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$'

validate_target() {
    local target="$1"
    [[ -z "$target" ]] && die "No se especificó objetivo (-t)"
    IFS=',' read -ra entries <<<"$target"
    for entry in "${entries[@]}"; do
        entry="${entry// /}"
        [[ -z "$entry" ]] && die "Objetivo vacío tras dividir por comas"
        if [[ "$entry" =~ $re_ip4 || "$entry" =~ $re_cidr ]]; then
            continue
        fi
        if command -v host >/dev/null 2>&1; then
            if ! host -t A "$entry" >/dev/null 2>&1; then
                die "Objetivo inválido (ni IPv4, ni CIDR, ni hostname resoluble): $entry"
            fi
        else
            die "Objetivo '$entry' no es IPv4/CIDR (sin 'host' disponible para resolver)"
        fi
    done
}

validate_ports() {
    [[ "$1" =~ $re_ports ]] || die "Formato de puertos inválido: $1"
    IFS=',' read -ra pr <<<"$1"
    for p in "${pr[@]}"; do
        if [[ "$p" =~ ^- ]]; then continue; fi
        local lo="${p%%-*}" hi="${p#*-}"
        [[ "$lo" =~ ^[0-9]+$ && "${hi}" =~ ^[0-9]+$ ]] || die "Rango de puertos inválido: $p"
        (( lo >= 1 && lo <= 65535 && hi >= lo && hi <= 65535 )) \
            || die "Rango de puertos fuera de límites (1-65535): $p"
    done
}

#------------------------------------------------------------------------------ argumentos
ARGS=""
while getopts "t:p:m:T:x:o:yv h" opt; do
    case "$opt" in
        t) TARGET="$OPTARG" ;;
        p) PORTS="$OPTARG" ;;
        m) PROFILE="$OPTARG" ;;
        T) TIMING="$OPTARG" ;;
        x) EXCLUDE="$OPTARG" ;;
        o) OUTPUT_DIR_ARG="$OPTARG" ;;
        y) CONFIRM_YES=true ;;
        v) VERBOSE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

TARGET="${TARGET:-}"
PORTS="${PORTS:-$DEFAULT_PORTS}"
PROFILE="${PROFILE:-$DEFAULT_PROFILE}"
TIMING="${TIMING:-$DEFAULT_TIMING}"
EXCLUDE="${EXCLUDE:-}"

if [[ -n "${1:-}" ]]; then
    TARGET="$1"
fi

[[ -z "$TARGET" ]] && { echo "Obligatorio: -t <objetivo>. Use -h para ayuda." >&2; exit "$EXIT_VALIDATION"; }
command -v nmap >/dev/null 2>&1 || die "Nmap no está instalado (instala con 'apt install nmap' o 'dnf install nmap')"

validate_target "$TARGET"
validate_ports "$PORTS"
[[ "$PROFILE" =~ ^(basic|service|os|full|udp)$ ]] || die "Perfil inválido: $PROFILE (use basic|service|os|full|udp)"
[[ "$TIMING" =~ ^[0-5]$ ]] || die "Plantilla de tiempos inválida: $TIMING (use 0-5)"

#------------------------------------------------------------------------------ checks de perfil
REQUIRE_ROOT=false
[[ "$PROFILE" == "os" || "$PROFILE" == "full" || "$PROFILE" == "udp" ]] && REQUIRE_ROOT=true
IS_ROOT=false
[[ "$EUID" -eq 0 ]] && IS_ROOT=true

CAN_SUDO=false
if ! $IS_ROOT && command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
        CAN_SUDO=true
    fi
fi

if $REQUIRE_ROOT; then
    if ! $IS_ROOT && ! $CAN_SUDO; then
        echo "[ERROR] El perfil '$PROFILE' requiere privilegios de root/sudo." >&2
        echo "        Ejecuta: sudo scan_nmap.sh -t $TARGET -m $PROFILE" >&2
        exit "$EXIT_PERMISSION"
    fi
    log "OK" "Perfil '$PROFILE' requiere root -> se usará sudo."
fi

#------------------------------------------------------------------------------ logging y salida
SCRIPT_DATE="$(date '+%Y%m%d_%H%M%S')"
BASE_DIR="${OUTPUT_DIR_ARG:-./informes}"
OBJECTIVE_DIR="$BASE_DIR/$(sane_name "$TARGET")_$SCRIPT_DATE"
mkdir -p "$OBJECTIVE_DIR"
LOGFILE="$OBJECTIVE_DIR/escaneo.log"
log "INFO" "Inicio del escaneo - objetivo=$TARGET perfil=$PROFILE puertos=$PORTS timing=$TIMING"
log "INFO" "Aviso legal: úsese únicamente sobre sistemas/redes autorizados."

#------------------------------------------------------------------------------ banners
banner() {
    cat <<EOF
==============================================================
  scan_nmap.sh  v${VERSION}  -  Escaneo de puertos (Nmap)
==============================================================
  Objetivo(s) : ${TARGET}
  Perfil     : ${PROFILE}
  Puertos    : ${PORTS}
  Timing     : T${TIMING}
  Excluir    : ${EXCLUDE:-ninguno}
  Salida     : ${OBJECTIVE_DIR}
  Fecha      : $(date '+%Y-%m-%d %H:%M:%S %Z')
==============================================================
  ATENCIÓN: úsese únicamente en sistemas/redes autorizados.
EOF
}

banner

if [[ "$CONFIRM_YES" != "true" ]]; then
    printf '\n¿Deseas continuar con el escaneo? [s/N] '
    read -r resp
    if [[ "${resp,,}" != "s" && "${resp,,}" != "si" && "${resp,,}" != "y" && "${resp,,}" != "yes" ]]; then
        echo "Cancelado por el usuario."
        exit "$EXIT_OK"
    fi
fi

#------------------------------------------------------------------------------ construcción del comando (arrays, sin eval)
if [[ -n "$EXCLUDE" ]]; then
    validate_target "$EXCLUDE"
fi

declare -A PROFILE_FLAGS=(
    [basic]="-sT"
    [service]="-sT -sV --version-intensity 7"
    [os]="-sS -O"
    [full]="-sS -A -O"
    [udp]="-sU --top-ports 200"
)
read -r -a PORTS_PROFILE <<< "${PROFILE_FLAGS[$PROFILE]}"

NMAP_CMD=(nmap)
if [[ "$REQUIRE_ROOT" == "true" && "$IS_ROOT" == "false" ]]; then
    NMAP_CMD=(sudo -n nmap)
fi

NMAP_CMD+=(-Pn -T"${TIMING}" --reason --stats-every 10s)
NMAP_CMD+=("${PORTS_PROFILE[@]}")
if [[ "$PROFILE" == "udp" ]]; then
    NMAP_CMD+=(--top-ports "$PORTS")
else
    NMAP_CMD+=(-p "$PORTS")
fi
if [[ -n "$EXCLUDE" ]]; then
    NMAP_CMD+=(--exclude "$EXCLUDE")
fi
[[ "$VERBOSE" == "true" ]] && NMAP_CMD+=(-v)
OUT_TXT="$OBJECTIVE_DIR/salida.txt"
OUT_XML="$OBJECTIVE_DIR/nmap.xml"
NMAP_CMD+=(-oN "$OUT_TXT" -oX "$OUT_XML")
read -r -a TARGETS <<< "$TARGET"
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=("$TARGET")
fi
NMAP_CMD+=("${TARGETS[@]}")

log "INFO" "Comando: ${NMAP_CMD[*]}"

#------------------------------------------------------------------------------ limpieza e interrupción
cleanup() {
    log "INFO" "Escaneo interrumpido."
    printf '\n[INFO] Escaneo interrumpido por el usuario.\n' >&2
    exit 130
}
trap cleanup INT TERM

#------------------------------------------------------------------------------ ejecución
echo
echo "Ejecutando Nmap... (puede tardar según el perfil)"
if ! "${NMAP_CMD[@]}"; then
    ec="$?"
    log "ERROR" "Nmap falló con código $ec"
    echo "[ERROR] Nmap falló (código $ec). Revisa: $LOGFILE" >&2
    exit "$EXIT_NMAP"
fi

#------------------------------------------------------------------------------ reporte
SUMMARY="$OBJECTIVE_DIR/resumen.txt"
{
    echo "Escaneo completado: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Objetivo: $TARGET | Perfil: $PROFILE | Puertos: $PORTS | Timing: T$TIMING"
    echo "------------------------------------------------------------"
} >"$SUMMARY"

OPEN_COUNT=0
if [[ -f "$OUT_TXT" ]]; then
    OPEN_COUNT=$(grep -cE '^[0-9]+/(tcp|udp)\s+open' "$OUT_TXT" || true)
    {
        echo "Puertos abiertos detectados: $OPEN_COUNT"
        echo "------------------------------------------------------------"
        grep -E '^[0-9]+/(tcp|udp)\s+open' "$OUT_TXT" || echo "(ninguno detectado)"
    } >>"$SUMMARY"
fi
echo "Resumen guardado en: $SUMMARY"

log "OK" "Fin del escaneo - puertos abiertos: $OPEN_COUNT"
exit "$EXIT_OK"