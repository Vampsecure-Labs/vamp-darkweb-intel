<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-darkweb-intel</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
  <img src="https://img.shields.io/badge/API%20keys-optional-brightgreen" alt="API keys optional"/>
  <img src="https://github.com/Vampsecure-Labs/vamp-darkweb-intel/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

**VampSecure Labs · Security Research Division**

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

`vamp-darkweb-intel` is a threat intelligence and darkweb research CLI that queries a target (domain, IP, hash, or URL) across multiple public feeds in parallel and **automatically correlates signals from independent sources**. When two or more sources flag the same indicator, the engine escalates severity — a C2 confirmed in both ThreatFox and OTX is more actionable than a single mention.

It works **without any API keys** using a curated set of free public feeds. Optional API keys (OTX, HIBP) unlock higher rate limits and additional data sources.

---

### Sources

| Source | Type | API key? | Target |
|--------|------|----------|--------|
| ThreatFox (abuse.ch) | IOC / C2 | No | Domain · IP · Hash · URL |
| URLhaus (abuse.ch) | Malware distribution | No | Domain · IP · URL |
| MalwareBazaar (abuse.ch) | Malware samples | No | Hash |
| RansomLook | Ransomware victims | No | Domain |
| Ransomware.live | Ransomware victims (recent) | No | Domain |
| GreyNoise Community | IP context (scanner / malicious) | No | IP |
| Shodan InternetDB | Open ports · CVEs | No | IP |
| AlienVault OTX | Threat intel pulses | Optional | Domain · IP · Hash |
| HackerTarget | IP geolocation | No | IP |
| Have I Been Pwned | Domain breach check | `HIBP_API_KEY` | Domain |

---

### Features

- Automatic target type detection: domain, IP, MD5/SHA1/SHA256 hash, or URL
- Parallel queries across all relevant sources (configurable workers)
- **Correlation engine**: if ≥2 independent sources flag the same category, severity escalates by one level
- Zero mandatory dependencies — only Python stdlib and `rich`
- Export to Console, JSON, HTML (dark-theme), Markdown, and CSV
- Exit codes suited for CI/CD pipelines (0 = clean, 1 = HIGH, 2 = CRITICAL)

---

### Requirements

- Python 3.9 or later
- `rich >= 13.7.0`

---

### Installation

```bash
git clone https://github.com/Vampsecure-Labs/vamp-darkweb-intel.git
cd vamp-darkweb-intel
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Or via PyPI:

```bash
pip install vamp-darkweb-intel
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-darkweb-intel
```

---

### Try it now

No setup required — these queries go to public free-tier feeds:

```bash
# Investigate an IP (GreyNoise + Shodan InternetDB + OTX + ThreatFox)
python3 vamp_darkweb_intel.py -t 1.1.1.1

# Check a domain for threat feed presence and ransomware victims
python3 vamp_darkweb_intel.py -t example.com

# Look up a known malware hash
python3 vamp_darkweb_intel.py -t 44d88612fea8a8f36de82e1278abb02f
```

> These targets will show INFO or CLEAN results — they are safe, well-known hosts and hashes used only to demonstrate the tool workflow.

---

### Examples

```bash
# Single domain investigation
python3 vamp_darkweb_intel.py -t suspicious-domain.com

# Multiple targets in one run
python3 vamp_darkweb_intel.py -t 185.220.101.1 -t evil-corp.biz

# Bulk investigation from file
python3 vamp_darkweb_intel.py --file iocs.txt --workers 10

# Force target type (useful for ambiguous inputs)
python3 vamp_darkweb_intel.py -t abc123def456... --type hash

# Export full results to all formats
python3 vamp_darkweb_intel.py -t 192.0.2.1 \
    --json results.json \
    --html report.html \
    --markdown report.md \
    --csv report.csv
```

---

### Optional API keys

Set these environment variables before running to unlock additional sources:

```bash
export OTX_API_KEY=your_key_here       # AlienVault OTX — extended rate limit
export HIBP_API_KEY=your_key_here      # Have I Been Pwned domain breach check
```

Copy `.env.example` to `.env` and fill in the keys you have:

```bash
cp .env.example .env
```

---

### Correlation engine

The engine cross-references findings by category across all sources. When two or more independent sources report the same finding category for a target, the highest-severity finding in that category is escalated by one level (up to CRITICAL).

**Example**: if ThreatFox reports `Threat Feed / MEDIUM` (confidence 50%) and OTX reports the same domain in 4 pulses (`Threat Intelligence / LOW`), the correlation engine adds a `MEDIUM → HIGH` escalated finding with a note listing both sources.

This reduces noise from low-confidence single-source hits while surfacing genuine threats confirmed by independent intelligence.

---

### CI/CD Integration

```yaml
name: Threat Intelligence Check
on:
  schedule:
    - cron: '0 8 * * 1'
  workflow_dispatch:

jobs:
  darkweb-intel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install vamp-darkweb-intel
      - run: |
          vamp-darkweb-intel \
            -t yourdomain.com \
            --json intel-results.json \
            --markdown intel-report.md
        # Exit 1 = HIGH findings, exit 2 = CRITICAL findings
        env:
          OTX_API_KEY: ${{ secrets.OTX_API_KEY }}
          HIBP_API_KEY: ${{ secrets.HIBP_API_KEY }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: intel-report
          path: intel-report.md
```

---

### CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-t / --target TARGET` | — | Investigation target: domain, IP, hash, or URL (repeatable) |
| `--file FILE` | — | Text file with one target per line |
| `--type TYPE` | auto | Force target type: `domain`, `ip`, `hash`, `url`, `email` |
| `--timeout N` | 12 | Per-source request timeout in seconds |
| `--workers N` | 6 | Parallel source queries |
| `--json FILE` | — | Export results to JSON |
| `--html FILE` | — | Export dark-theme HTML report |
| `--markdown FILE` | — | Export Markdown report |
| `--csv FILE` | — | Export CSV results |

---

### Exit Codes

| Code | Meaning | CI/CD Behavior |
|------|---------|----------------|
| `0` | Clean — no HIGH or CRITICAL findings | Pipeline passes |
| `1` | HIGH-severity findings detected | Pipeline fails — review required |
| `2` | CRITICAL findings detected | Pipeline fails — immediate action required |

---

### Severity levels

| Level | Examples |
|-------|---------|
| CRITICAL | Active C2/botnet confirmed · malware hash confirmed · CVEs on exposed service |
| HIGH | IOC in threat feed · ransomware victim confirmed · IP classified malicious |
| MEDIUM | Low-confidence IOC · IP active scanner · multi-source correlation upgrade |
| LOW | Mentioned in old intelligence · minor open port surface |
| INFO | Geolocation data · known-good infrastructure (RIOT) |

---

### Sample Output

```bash
$ python3 vamp_darkweb_intel.py -t 192.0.2.47 -t malware-sample.example.org
  vamp-darkweb-intel v1.2 — Threat Intelligence CLI
  Targets: 2 | Sources: ThreatFox · URLhaus · GreyNoise · Shodan · OTX · RansomLook
  ────────────────────────────────────────────────────────────

  Target: 192.0.2.47 (IP)
  ┌─────────────────────────────────────────────────────────┐
  │  [HIGH]      GreyNoise: malicious scanner (Mirai botnet) │
  │  [MEDIUM]    ThreatFox: C2 indicator (confidence 62%)    │
  │  [INFO]      Shodan InternetDB: ports 22/80/443/8080     │
  │  [HIGH] ★   CORRELATION: ThreatFox + GreyNoise agree    │
  │              → Escalated: MEDIUM → HIGH (2 sources)      │
  └─────────────────────────────────────────────────────────┘

  Target: malware-sample.example.org (Domain)
  ┌─────────────────────────────────────────────────────────┐
  │  [CRITICAL]  ThreatFox: active C2 (AgentTesla RAT)      │
  │  [HIGH]      URLhaus: malware distribution confirmed     │
  │  [HIGH]      OTX: 12 threat intelligence pulses          │
  │  [CRITICAL] ★ CORRELATION: 3 independent sources agree  │
  │               → Escalated: HIGH → CRITICAL               │
  └─────────────────────────────────────────────────────────┘

  ────────────────────────────────────────────────────────────
  Targets: 2 | Raw findings: 7 | Correlations triggered: 2
  CRITICAL: 1 | HIGH: 3 | MEDIUM: 1 | INFO: 1
  Exit code: 2
```

---

### Why vamp-darkweb-intel vs. DarkOwl · Recorded Future · SpiderFoot

| Feature | vamp-darkweb-intel | DarkOwl | Recorded Future | SpiderFoot |
|---------|:-----------------:|:-------:|:---------------:|:----------:|
| No mandatory API keys | ✅ 8/10 sources free | ❌ paid | ❌ paid | ⚠️ free tier limited |
| Multi-source correlation engine | ✅ | ❌ | ✅ | ❌ |
| STIX 2.1 aligned output | ✅ | ✅ | ✅ | ❌ |
| Self-hosted / no cloud dependency | ✅ | ❌ SaaS | ❌ SaaS | ✅ |
| Ransomware victim check (RansomLook + Ransom.live) | ✅ | ⚠️ | ✅ | ⚠️ |
| HIBP domain breach check | ✅ | ❌ | ❌ | ⚠️ |
| CI/CD pipeline integration (exit codes) | ✅ | ❌ | ❌ | ❌ |
| Bulk IOC file processing | ✅ | ⚠️ API | ✅ | ✅ |
| MITRE ATT&CK technique mapping | ✅ | ⚠️ | ✅ | ❌ |
| MalwareBazaar hash lookup | ✅ | ❌ | ⚠️ | ⚠️ |

- **Correlation engine**: severity escalates automatically when two or more independent sources flag the same indicator — reduces single-source false positives while preserving genuine threats confirmed by independent intelligence.
- **Zero-cost operation**: 8 of 10 sources require no API key whatsoever — full threat investigation without any budget or account registration.
- **CI/CD native**: structured exit codes (0 / 1 / 2) enable direct integration into weekly scheduled threat monitoring pipelines without additional parsing.

---

### Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| DWI-001 | IOC confirmed in ThreatFox C2 / malware distribution feed | STIX 2.1 Indicator | CRITICAL |
| DWI-002 | URL or domain in URLhaus active malware distribution list | STIX 2.1 Indicator | HIGH |
| DWI-003 | File hash confirmed as malware in MalwareBazaar | STIX 2.1 Malware | CRITICAL |
| DWI-004 | Organization or domain confirmed as ransomware victim | STIX 2.1 Incident | HIGH |
| DWI-005 | IP classified malicious by GreyNoise (active threat actor) | ATT&CK T1595 | HIGH |
| DWI-006 | IP flagged as active mass scanner by GreyNoise (RIOT: false) | ATT&CK T1595.001 | MEDIUM |
| DWI-007 | AlienVault OTX pulse count ≥ 5 (active threat actor interest) | MITRE ATT&CK CTI | HIGH |
| DWI-008 | Known CVEs on open ports per Shodan InternetDB | CVSS 3.1 / NVD | HIGH |
| DWI-009 | Domain confirmed in Have I Been Pwned breach dataset | GDPR Art. 33 | HIGH |
| DWI-010 | Multi-source correlation — same category flagged by ≥ 2 sources | STIX 2.1 Bundle | escalation |

---

### Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

---

### Part of VampSecure Labs Toolkit

`vamp-darkweb-intel` is part of the VampSecure Labs security research toolkit.

- Portfolio: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orchestrator: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

---

### Version History

| Version | Main changes |
|---------|-------------|
| v1.2 | Bilingual README (EN/ES) |
| v1.1.0 | Monitor continuo |
| v1.0 | Initial release — multi-source threat intelligence CLI with correlation engine |

---

© VampSecure Studios — VampSecure Labs Security Research Division

---
---

<a name="español"></a>
## 🇪🇸 Español

`vamp-darkweb-intel` es una CLI de investigación de inteligencia de amenazas y darkweb que consulta un objetivo (dominio, IP, hash o URL) en múltiples feeds públicos en paralelo y **correlaciona automáticamente señales de fuentes independientes**. Cuando dos o más fuentes marcan el mismo indicador, el motor escala la severidad — un C2 confirmado tanto en ThreatFox como en OTX es más accionable que una sola mención.

Funciona **sin ninguna clave API** usando un conjunto curado de feeds públicos gratuitos. Las claves API opcionales (OTX, HIBP) desbloquean mayores límites de tasa y fuentes de datos adicionales.

---

### Fuentes

| Fuente | Tipo | ¿Clave API? | Objetivo |
|--------|------|-------------|----------|
| ThreatFox (abuse.ch) | IOC / C2 | No | Dominio · IP · Hash · URL |
| URLhaus (abuse.ch) | Distribución de malware | No | Dominio · IP · URL |
| MalwareBazaar (abuse.ch) | Muestras de malware | No | Hash |
| RansomLook | Víctimas de ransomware | No | Dominio |
| Ransomware.live | Víctimas de ransomware (recientes) | No | Dominio |
| GreyNoise Community | Contexto IP (escáner / malicioso) | No | IP |
| Shodan InternetDB | Puertos abiertos · CVEs | No | IP |
| AlienVault OTX | Pulsos de inteligencia de amenazas | Opcional | Dominio · IP · Hash |
| HackerTarget | Geolocalización IP | No | IP |
| Have I Been Pwned | Comprobación de brechas por dominio | `HIBP_API_KEY` | Dominio |

---

### Características

- Detección automática del tipo de objetivo: dominio, IP, hash MD5/SHA1/SHA256 o URL
- Consultas paralelas en todas las fuentes relevantes (workers configurables)
- **Motor de correlación**: si ≥2 fuentes independientes marcan la misma categoría, la severidad se escala un nivel
- Sin dependencias obligatorias — solo stdlib de Python y `rich`
- Exportación a consola, JSON, HTML (dark-theme), Markdown y CSV
- Exit codes adecuados para pipelines CI/CD (0 = limpio, 1 = HIGH, 2 = CRITICAL)

---

### Requisitos

- Python 3.9 o posterior
- `rich >= 13.7.0`

---

### Instalación

```bash
git clone https://github.com/Vampsecure-Labs/vamp-darkweb-intel.git
cd vamp-darkweb-intel
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

O vía PyPI:

```bash
pip install vamp-darkweb-intel
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-darkweb-intel
```

---

### Pruébalo ahora

Sin configuración previa — estas consultas van a feeds públicos de nivel gratuito:

```bash
# Investigar una IP (GreyNoise + Shodan InternetDB + OTX + ThreatFox)
python3 vamp_darkweb_intel.py -t 1.1.1.1

# Comprobar un dominio en feeds de amenazas y víctimas de ransomware
python3 vamp_darkweb_intel.py -t example.com

# Buscar un hash de malware conocido
python3 vamp_darkweb_intel.py -t 44d88612fea8a8f36de82e1278abb02f
```

> Estos objetivos mostrarán resultados INFO o CLEAN — son hosts y hashes conocidos y seguros, usados solo para demostrar el flujo de la herramienta.

---

### Ejemplos

```bash
# Investigación de un único dominio
python3 vamp_darkweb_intel.py -t dominio-sospechoso.com

# Múltiples objetivos en una sola ejecución
python3 vamp_darkweb_intel.py -t 185.220.101.1 -t evil-corp.biz

# Investigación masiva desde fichero
python3 vamp_darkweb_intel.py --file iocs.txt --workers 10

# Forzar tipo de objetivo (útil para entradas ambiguas)
python3 vamp_darkweb_intel.py -t abc123def456... --type hash

# Exportar resultados completos a todos los formatos
python3 vamp_darkweb_intel.py -t 192.0.2.1 \
    --json resultados.json \
    --html informe.html \
    --markdown informe.md \
    --csv informe.csv
```

---

### Claves API opcionales

Establece estas variables de entorno antes de ejecutar para desbloquear fuentes adicionales:

```bash
export OTX_API_KEY=tu_clave_aqui       # AlienVault OTX — límite de tasa extendido
export HIBP_API_KEY=tu_clave_aqui      # Have I Been Pwned — comprobación de brechas por dominio
```

Copia `.env.example` a `.env` y rellena las claves que tengas:

```bash
cp .env.example .env
```

---

### Motor de correlación

El motor cruza los hallazgos por categoría en todas las fuentes. Cuando dos o más fuentes independientes informan de la misma categoría de hallazgo para un objetivo, el hallazgo de mayor severidad en esa categoría se escala un nivel (hasta CRITICAL).

**Ejemplo**: si ThreatFox reporta `Feed de Amenazas / MEDIUM` (confianza 50%) y OTX reporta el mismo dominio en 4 pulsos (`Inteligencia de Amenazas / LOW`), el motor de correlación añade un hallazgo escalado `MEDIUM → HIGH` con una nota que lista ambas fuentes.

Esto reduce el ruido de los hits de baja confianza de una sola fuente mientras aflora las amenazas genuinas confirmadas por inteligencia independiente.

---

### Integración CI/CD

```yaml
name: Threat Intelligence Check
on:
  schedule:
    - cron: '0 8 * * 1'
  workflow_dispatch:

jobs:
  darkweb-intel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install vamp-darkweb-intel
      - run: |
          vamp-darkweb-intel \
            -t tudominio.com \
            --json intel-resultados.json \
            --markdown intel-informe.md
        # Exit 1 = hallazgos HIGH, exit 2 = hallazgos CRITICAL
        env:
          OTX_API_KEY: ${{ secrets.OTX_API_KEY }}
          HIBP_API_KEY: ${{ secrets.HIBP_API_KEY }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: intel-informe
          path: intel-informe.md
```

---

### Referencia CLI

| Flag | Por defecto | Descripción |
|------|-------------|-------------|
| `-t / --target OBJETIVO` | — | Objetivo de investigación: dominio, IP, hash o URL (repetible) |
| `--file FICHERO` | — | Fichero de texto con un objetivo por línea |
| `--type TIPO` | auto | Forzar tipo de objetivo: `domain`, `ip`, `hash`, `url`, `email` |
| `--timeout N` | 12 | Timeout de petición por fuente en segundos |
| `--workers N` | 6 | Consultas de fuentes en paralelo |
| `--json FICHERO` | — | Exportar resultados a JSON |
| `--html FICHERO` | — | Exportar informe HTML dark-theme |
| `--markdown FICHERO` | — | Exportar informe Markdown |
| `--csv FICHERO` | — | Exportar resultados CSV |

---

### Exit codes

| Código | Significado | Comportamiento CI/CD |
|--------|-------------|----------------------|
| `0` | Limpio — sin hallazgos HIGH o CRITICAL | El pipeline pasa |
| `1` | Hallazgos de severidad HIGH detectados | El pipeline falla — revisión requerida |
| `2` | Hallazgos CRITICAL detectados | El pipeline falla — acción inmediata requerida |

---

### Niveles de severidad

| Nivel | Ejemplos |
|-------|---------|
| CRITICAL | C2/botnet activo confirmado · hash de malware confirmado · CVEs en servicio expuesto |
| HIGH | IOC en feed de amenazas · víctima de ransomware confirmada · IP clasificada como maliciosa |
| MEDIUM | IOC de baja confianza · IP escáner activo · upgrade por correlación multi-fuente |
| LOW | Mencionado en inteligencia antigua · superficie de puerto abierto menor |
| INFO | Datos de geolocalización · infraestructura conocida-buena (RIOT) |

---

### Salida de ejemplo

```bash
$ python3 vamp_darkweb_intel.py -t 192.0.2.47 -t malware-muestra.ejemplo.org
  vamp-darkweb-intel v1.2 — Threat Intelligence CLI
  Objetivos: 2 | Fuentes: ThreatFox · URLhaus · GreyNoise · Shodan · OTX · RansomLook
  ────────────────────────────────────────────────────────────

  Objetivo: 192.0.2.47 (IP)
  ┌─────────────────────────────────────────────────────────┐
  │  [HIGH]      GreyNoise: escáner malicioso (botnet Mirai) │
  │  [MEDIUM]    ThreatFox: indicador C2 (confianza 62%)     │
  │  [INFO]      Shodan InternetDB: puertos 22/80/443/8080   │
  │  [HIGH] ★   CORRELACIÓN: ThreatFox + GreyNoise coinciden│
  │              → Escalado: MEDIUM → HIGH (2 fuentes)       │
  └─────────────────────────────────────────────────────────┘

  Objetivo: malware-muestra.ejemplo.org (Dominio)
  ┌─────────────────────────────────────────────────────────┐
  │  [CRITICAL]  ThreatFox: C2 activo (RAT AgentTesla)       │
  │  [HIGH]      URLhaus: distribución de malware confirmada  │
  │  [HIGH]      OTX: 12 pulsos de inteligencia de amenazas  │
  │  [CRITICAL] ★ CORRELACIÓN: 3 fuentes independientes     │
  │               → Escalado: HIGH → CRITICAL                │
  └─────────────────────────────────────────────────────────┘

  ────────────────────────────────────────────────────────────
  Objetivos: 2 | Hallazgos brutos: 7 | Correlaciones activadas: 2
  CRITICAL: 1 | HIGH: 3 | MEDIUM: 1 | INFO: 1
  Exit code: 2
```

---

### Why vamp-darkweb-intel vs. DarkOwl · Recorded Future · SpiderFoot

| Feature | vamp-darkweb-intel | DarkOwl | Recorded Future | SpiderFoot |
|---------|:-----------------:|:-------:|:---------------:|:----------:|
| Sin claves API obligatorias | ✅ 8/10 fuentes gratuitas | ❌ de pago | ❌ de pago | ⚠️ nivel gratuito limitado |
| Motor de correlación multi-fuente | ✅ | ❌ | ✅ | ❌ |
| Salida alineada con STIX 2.1 | ✅ | ✅ | ✅ | ❌ |
| Auto-hospedado / sin dependencia cloud | ✅ | ❌ SaaS | ❌ SaaS | ✅ |
| Comprobación víctimas ransomware (RansomLook + Ransom.live) | ✅ | ⚠️ | ✅ | ⚠️ |
| Comprobación de brechas HIBP por dominio | ✅ | ❌ | ❌ | ⚠️ |
| Integración pipeline CI/CD (exit codes) | ✅ | ❌ | ❌ | ❌ |
| Procesamiento masivo de IOC desde fichero | ✅ | ⚠️ API | ✅ | ✅ |
| Mapeo de técnicas MITRE ATT&CK | ✅ | ⚠️ | ✅ | ❌ |
| Búsqueda de hashes en MalwareBazaar | ✅ | ❌ | ⚠️ | ⚠️ |

- **Motor de correlación**: la severidad se escala automáticamente cuando dos o más fuentes independientes marcan el mismo indicador — reduce los falsos positivos de fuente única preservando las amenazas genuinas confirmadas por inteligencia independiente.
- **Operación de coste cero**: 8 de 10 fuentes no requieren ninguna clave API — investigación completa de amenazas sin presupuesto ni registro de cuentas.
- **Nativo para CI/CD**: los exit codes estructurados (0 / 1 / 2) permiten la integración directa en pipelines de monitorización de amenazas programada semanalmente sin parsing adicional.

---

### Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| DWI-001 | IOC confirmed in ThreatFox C2 / malware distribution feed | STIX 2.1 Indicator | CRITICAL |
| DWI-002 | URL or domain in URLhaus active malware distribution list | STIX 2.1 Indicator | HIGH |
| DWI-003 | File hash confirmed as malware in MalwareBazaar | STIX 2.1 Malware | CRITICAL |
| DWI-004 | Organization or domain confirmed as ransomware victim | STIX 2.1 Incident | HIGH |
| DWI-005 | IP classified malicious by GreyNoise (active threat actor) | ATT&CK T1595 | HIGH |
| DWI-006 | IP flagged as active mass scanner by GreyNoise (RIOT: false) | ATT&CK T1595.001 | MEDIUM |
| DWI-007 | AlienVault OTX pulse count ≥ 5 (active threat actor interest) | MITRE ATT&CK CTI | HIGH |
| DWI-008 | Known CVEs on open ports per Shodan InternetDB | CVSS 3.1 / NVD | HIGH |
| DWI-009 | Domain confirmed in Have I Been Pwned breach dataset | RGPD Art. 33 | HIGH |
| DWI-010 | Multi-source correlation — same category flagged by ≥ 2 sources | STIX 2.1 Bundle | escalation |

---

### Aviso legal

Uso exclusivo en sistemas propios o para los que se dispone de autorización escrita explícita del titular del sistema. VampSecure Studios no asume responsabilidad por el uso no autorizado.

---

### Parte del toolkit VampSecure Labs

`vamp-darkweb-intel` es parte del toolkit de investigación de seguridad de VampSecure Labs.

- Portfolio: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orquestador: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

---

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.2 | README bilingüe (EN/ES) |
| v1.1.0 | Monitor continuo |
| v1.0 | Release inicial — CLI de inteligencia de amenazas multi-fuente con motor de correlación |

---

© VampSecure Studios — VampSecure Labs Security Research Division
