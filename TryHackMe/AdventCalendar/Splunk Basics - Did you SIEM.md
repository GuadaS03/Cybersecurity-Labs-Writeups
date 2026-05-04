# Splunk Basics — Did you SIEM?
> **TryHackMe · Advent of Cyber 2025 · Day 3**  
> 🟡 Medium · SIEM · Log Analysis · Threat Detection  
---

## Contexto del escenario

Durante las fiestas, el equipo SOC de una organización detectó comportamiento anómalo en su servidor web. Alguien llamado **King Malhare** y sus "Bandit Bunnies" lanzaron un ataque coordinado contra la infraestructura. Mi tarea: usar **Splunk** para analizar los logs, reconstruir la cadena de ataque e identificar al atacante.

Los datos ya estaban pre-ingestados en Splunk con dos sourcetypes:
- `web_traffic` → logs de conexiones al servidor web
- `firewall_logs` → tráfico permitido/bloqueado por el firewall

IP del servidor comprometido: `10.10.1.15`

---

## Herramientas utilizadas

| Herramienta | Uso |
|---|---|
| Splunk Enterprise | Plataforma SIEM principal |
| SPL (Search Processing Language) | Consultas y correlación de eventos |
| Splunk Search & Reporting | Análisis de logs |
| Splunk Visualizations | Gráficos de timeline y volumen |

---

## Desarrollo paso a paso

### 1. Exploración inicial de los logs

Arranqué con la query más básica para entender qué datos había disponibles:

```spl
index=main
```

Esto trajo **todos los eventos** del índice principal. Para verificar los sourcetypes disponibles, hice click en el campo `sourcetype` en el panel izquierdo. Confirmé los dos datasets: `web_traffic` y `firewall_logs`.

Luego enfoqué en el tráfico web:

```spl
index=main sourcetype=web_traffic
```

**Resultado:** 17.172 eventos en total. Al revisar los campos extraídos automáticamente por Splunk vi `user_agent`, `path`, `client_ip` y `status` — exactamente los campos que necesitaba para el análisis.

---

### 2. Visualización del timeline — ¿cuándo ocurrió el ataque?

Para identificar el período de mayor actividad, agrupé los eventos por día:

```spl
index=main sourcetype=web_traffic | timechart span=1d count
```

Fui a la pestaña **Visualization** para ver el gráfico de barras. Se notaba claramente un pico anormal en un día específico. Para ordenarlo de mayor a menor:

```spl
index=main sourcetype=web_traffic | timechart span=1d count | sort by count | reverse
```

> **🚩 Flag 1 — Día con mayor tráfico: `2025-10-12`**

El pico era masivo comparado con el tráfico diario normal. Ese era el día del ataque principal.

---

### 3. Detección de anomalías — Análisis de campos sospechosos

#### User Agents

Hice click en el campo `user_agent` en el panel izquierdo. Además de agentes legítimos (Mozilla, Chrome, Safari), aparecieron strings muy sospechosos: herramientas de escaneo, scripts automatizados, y nombres de exploits conocidos.

#### Client IPs

Al revisar `client_ip`, una IP se destacaba por un volumen desproporcionado de requests. La anoté para investigarla.

#### Paths

El campo `path` mostraba rutas directamente asociadas a ataques: intentos de acceder a `.env`, `phpinfo`, archivos de backup, y comandos de shell.

---

### 4. Filtrado del tráfico benigno

Para eliminar el ruido del tráfico legítimo y enfocarse en lo malicioso:

```spl
index=main sourcetype=web_traffic 
user_agent!=*Mozilla* 
user_agent!=*Chrome* 
user_agent!=*Safari* 
user_agent!=*Firefox*
```

Al hacer click en `client_ip` con esta query filtrada, **una sola IP era responsable de todo el tráfico malicioso**.

Para confirmarlo con estadísticas:

```spl
sourcetype=web_traffic 
user_agent!=*Mozilla* 
user_agent!=*Chrome* 
user_agent!=*Safari* 
user_agent!=*Firefox* 
| stats count by client_ip 
| sort -count 
| head 5
```

> **🚩 Flag 1 — IP del atacante: `198.51.100.55`**

---

### 5. Reconstrucción de la cadena de ataque

Con la IP del atacante identificada, reconstruí cada fase del ataque cronológicamente.

#### Fase 1 — Reconocimiento (Footprinting)

El atacante empezó probando archivos de configuración expuestos:

```spl
sourcetype=web_traffic client_ip="198.51.100.55" 
AND path IN ("/.env", "/*phpinfo*", "/.git*") 
| table _time, path, user_agent, status
```

**Resultado:** requests con `curl` y `wget` hacia `.env` y `.git`, recibiendo respuestas 404/403/401. El atacante mapeó la superficie de ataque antes de explotar.

---

#### Fase 2 — Enumeración (Path Traversal)

Después pasó a buscar vulnerabilidades de path traversal y open redirects:

```spl
sourcetype=web_traffic client_ip="198.51.100.55" 
AND path="*..\/..\/*" OR path="*redirect*" 
| stats count by path
```

**Resultado:** 658 intentos de path traversal buscando acceder a archivos del sistema fuera del webroot.

> **🚩 Flag — Path traversal attempts: `658`**

---

#### Fase 3 — SQL Injection

El atacante escaló a inyección SQL automatizada con herramientas conocidas:

```spl
sourcetype=web_traffic client_ip="198.51.100.55" 
AND user_agent IN ("*sqlmap*", "*Havij*") 
| table _time, path, status
```

**Resultado:** Payloads con `SLEEP(5)` confirmando SQL injection basada en tiempo. Los status codes 504 (Gateway Timeout) confirmaron que la inyección fue exitosa — el servidor esperó el tiempo del `SLEEP`.

> **🚩 Flag — Eventos de Havij user_agent: `993`**

---

#### Fase 4 — Exfiltración de datos

Luego buscó archivos grandes y sensibles para descargar:

```spl
sourcetype=web_traffic client_ip="198.51.100.55" 
AND path IN ("*backup.zip*", "*logs.tar.gz*") 
| table _time, path, user_agent
```

**Resultado:** Requests de `logs.tar.gz` y archivos de backup usando `curl`, `zgrab` y otras herramientas. El atacante estaba extrayendo logs comprimidos — preparación para **double extortion ransomware**.

---

#### Fase 5 — RCE y Ransomware (Objetivo Final)

La query más crítica de todo el análisis:

```spl
sourcetype=web_traffic client_ip="198.51.100.55" 
AND path IN ("*bunnylock.bin*", "*shell.php?cmd=*") 
| table _time, path, user_agent, status
```

**Resultado:** El comando `shell.php?cmd=./bunnylock.bin` ejecutado con status 200 ✅. Esto confirma:
1. El atacante subió un **webshell** (`shell.php`) al servidor
2. Usó el webshell para ejecutar **código arbitrario** (RCE)
3. Ejecutó `bunnylock.bin` — el payload de ransomware

El servidor estaba completamente comprometido.

---

### 6. Correlación con firewall logs — Confirmación del C2

Pivoté a los `firewall_logs` para confirmar la comunicación Command & Control post-compromiso:

```spl
sourcetype=firewall_logs 
src_ip="10.10.1.5" 
AND dest_ip="198.51.100.55" 
AND action="ALLOWED" 
| table _time, action, protocol, src_ip, dest_ip, dest_port, reason
```

**Resultado:** El servidor comprometido (`10.10.1.5`) estableció conexiones **salientes** hacia la IP del atacante. El campo `REASON=C2_CONTACT` en los logs confirma que el firewall identificó (pero permitió) comunicación C2.

Finalmente, calculé el volumen total exfiltrado:

```spl
sourcetype=firewall_logs 
src_ip="10.10.1.5" 
AND dest_ip="198.51.100.55" 
AND action="ALLOWED" 
| stats sum(bytes_transferred) by src_ip
```

> **🚩 Flag — Bytes transferidos al C2: `126167`**

---

## Línea de tiempo del ataque (resumen)

```
2025-10-12
│
├── Reconocimiento
│   └── curl/wget → /.env, /.git, /phpinfo  [404/403]
│
├── Enumeración  
│   └── 658 intentos de path traversal  [400/403]
│
├── Explotación
│   └── sqlmap + Havij → SQL Injection con SLEEP(5)  [504 ✓]
│
├── Exfiltración inicial
│   └── curl/zgrab → /logs.tar.gz, /backup.zip
│
├── Persistencia (RCE)
│   └── shell.php?cmd=./bunnylock.bin  [200 ✓]  ← PUNTO CRÍTICO
│
└── C2 activo
    └── 10.10.1.5 → 198.51.100.55 → 126.167 bytes exfiltrados
```

---

## Resumen de flags

| Pregunta | Respuesta |
|---|---|
| IP del atacante | `198.51.100.55` |
| Día de mayor tráfico | `2025-10-12` |
| Eventos con Havij user_agent | `993` |
| Intentos de path traversal | `658` |
| Bytes transferidos al C2 | `126167` |

---

## Conceptos clave aprendidos

### ¿Por qué un SIEM cambia todo?

Sin Splunk, detectar este ataque hubiera requerido revisar manualmente **17.172 líneas de log**. Con SPL, encontré el patrón completo en minutos. La clave no es encontrar un evento malo — es **correlacionar eventos normales que juntos forman un ataque**.

### SPL — Comandos más útiles en este room

| Comando | Para qué lo usé |
|---|---|
| `index=main sourcetype=X` | Filtrar por fuente de datos |
| `timechart span=1d count` | Detectar el pico de actividad |
| `stats count by campo` | Identificar la IP dominante |
| `sort -count \| head 5` | Top 5 IPs maliciosas |
| `table _time, path, status` | Ver cronología del ataque |
| `stats sum(bytes_transferred)` | Calcular volumen exfiltrado |
| `user_agent!=*Mozilla*` | Filtrar tráfico legítimo |

### La cadena de ataque (kill chain)

Este room demostró en la práctica el ciclo completo:
**Reconocimiento → Enumeración → Explotación → Acceso inicial → Movimiento lateral → Exfiltración → C2**

Cada fase deja huellas en los logs. El trabajo del analista SOC es leerlas en orden.

### Pivot entre sourcetypes

Uno de los aspectos más valiosos fue **pivotar entre `web_traffic` y `firewall_logs`** usando la misma IP como eje. Los logs web mostraron el ataque entrante; los firewall logs confirmaron la comunicación C2 saliente. Ningún sourcetype solo cuenta la historia completa.

---

## Reflexión personal

Lo que más me impactó de este room fue entender que el **tiempo importa más que la herramienta**. El atacante usó curl, sqlmap, y un webshell básico — nada sofisticado. Lo que lo hizo peligroso fue la velocidad y metodología con la que encadenó las fases.

También aprendí que filtrar primero el ruido (excluir Mozilla/Chrome/Safari) es más efectivo que buscar lo malicioso directamente. En un entorno real con millones de eventos, esa diferencia de enfoque determina si encontrás el ataque o lo perdés en el ruido.

---

## Referencias

- [TryHackMe — Advent of Cyber 2025](https://tryhackme.com/christmas)
- [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK — T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [Windows Event ID Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

---

*Write-up por [Guadalupe Savall](https://linkedin.com/in/guadalupesavall) · San Juan, Argentina*  
*Este write-up es con fines educativos. Todos los entornos son simulados dentro de TryHackMe.*