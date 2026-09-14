# scan_nmap.sh

Herramienta de línea de comandos para escaneo de puertos con **Nmap**, diseñada con enfoque de ciberseguridad.

> **ADVERTENCIA**: úsese únicamente en sistemas y redes en las que se tiene autorización expresa.
> El escaneo no autorizado puede ser ilegal. El autor no se hace responsable del mal uso.

## Requisitos

- Bash ≥ 4.0
- Nmap ≥ 7 (instalar con `apt install nmap` o `dnf install nmap`)
- `host` (opcional, para validar hostnames)
- `sudo` no interactivo (opcional, para perfiles que requieren root)

## Uso

```bash
./scan_nmap.sh -t <objetivo> [opciones]
```

### Opciones

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `-t <objetivo>` | IP, rango CIDR o múltiples separados por comas (obligatoria) | `8.8.8.8`, `192.168.1.0/24`, `10.0.0.1,10.0.0.2` |
| `-p <puertos>` | Puertos o rangos. Default: `1-1000` | `22,80,443`, `1-65535` |
| `-m <perfil>` | Perfil de escaneo. Default: `basic` | `basic`, `service`, `os`, `full`, `udp` |
| `-T <0-5>` | Plantilla de tiempos. Default: `4` | `-T 1` (sigiloso) |
| `-x <excluir>` | IPs/rangos a excluir | `-x 192.168.1.0/24` |
| `-o <dir>` | Directorio de salida. Default: `./informes` | `-o ./escaneos` |
| `-y` | Omitir confirmación (CI) | |
| `-v` | Verboso (pasa `-v` a Nmap) | |
| `-h` | Ayuda | |

### Perfiles

| Perfil | Flags | Requiere root |
|--------|-------|:-------------:|
| `basic` | `-sT` (connect) | No |
| `service` | `-sT -sV --version-intensity 7` | No |
| `os` | `-sS -O` | Sí |
| `full` | `-sS -A -O` (agresivo) | Sí |
| `udp` | `-sU --top-ports 200` | Sí |

### Ejemplos

```bash
./scan_nmap.sh -t 192.168.1.10
./scan_nmap.sh -t 192.168.1.10 -m service -p 22,80,443,8080
sudo ./scan_nmap.sh -t 10.0.0.0/24 -m full -x 10.0.0.1
./scan_nmap.sh -t 8.8.8.8 -m service -T 3 -v -o ./escaneos
```

## Salida

Cada ejecución crea un directorio `informes/<objetivo>_<fecha_hora>/` con:

- `salida.txt` — salida normal de Nmap
- `nmap.xml` — salida XML (parseable)
- `resumen.txt` — resumen con puertos abiertos
- `escaneo.log` — log con timestamps

## Códigos de salida

| Código | Significado |
|:------:|-------------|
| 0 | Escaneo completado |
| 1 | Error de validación |
| 2 | Permisos insuficientes |
| 3 | Nmap falló |

## Seguridad

- Validación estricta de entradas (IP/CIDR, puertos, perfiles) antes de ejecutar
- Construcción del comando con arrays de bash (sin `eval`), evita inyección de comandos
- No ejecuta scripts NSE peligrosos por defecto