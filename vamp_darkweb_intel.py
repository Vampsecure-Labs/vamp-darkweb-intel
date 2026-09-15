#!/usr/bin/env python3
"""
vamp_darkweb_intel.py — Motor de Inteligencia Darkweb y Threat Intelligence
============================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Investigaciones de Seguridad Autorizadas — v1.0

DESCRIPCIÓN
-----------
Consulta cruzada de un objetivo (dominio, IP, hash, URL) contra múltiples
fuentes públicas de threat intelligence. El motor de correlación escala
automáticamente la severidad cuando una IOC aparece en varias fuentes.

FUENTES GRATUITAS (sin clave API)
----------------------------------
  ThreatFox (abuse.ch)       — IOCs activos (dominio/IP/URL/hash/C2)
  URLhaus (abuse.ch)         — URLs maliciosas activas y archivadas
  MalwareBazaar (abuse.ch)   — Muestras de malware por hash o firma
  RansomLook                 — Víctimas de ransomware por dominio/nombre
  Ransomware.live            — Víctimas recientes de ransomware
  GreyNoise Community        — Contexto de IP (escáner/malicioso/benigno)
  Shodan InternetDB          — Puertos, etiquetas y CVEs de IP (sin auth)
  AlienVault OTX             — Pulsos de inteligencia (límite reducido sin clave)
  HackerTarget               — Geolocalización y DNS inverso de IP

FUENTES OPCIONALES (con clave API en variables de entorno)
-----------------------------------------------------------
  OTX_API_KEY                — AlienVault OTX con límite extendido
  HIBP_API_KEY               — Have I Been Pwned (dominios y emails)

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

VERSION   = "1.0"
TOOL_NAME = "vamp-darkweb-intel"

_TIMEOUT = 12  # segundos por petición

# Endpoints
_THREATFOX_API       = "https://threatfox-api.abuse.ch/api/v1/"
_URLHAUS_HOST_API    = "https://urlhaus-api.abuse.ch/v1/host/"
_URLHAUS_URL_API     = "https://urlhaus-api.abuse.ch/v1/url/"
_BAZAAR_API          = "https://mb-api.abuse.ch/api/v1/"
_RANSOMLOOK_RECENT   = "https://www.ransomlook.io/api/recent"
_RANSOMWARELIVE_API  = "https://api.ransomware.live/v2/recentvictims"
_GREYNOISE_COMM      = "https://api.greynoise.io/v3/community/{ip}"
_SHODAN_INTERNETDB   = "https://internetdb.shodan.io/{ip}"
_OTX_DOMAIN          = "https://otx.alienvault.com/api/v1/indicators/domain/{target}/general"
_OTX_IP              = "https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general"
_OTX_HASH            = "https://otx.alienvault.com/api/v1/indicators/file/{target}/general"
_HACKERTARGET_GEO    = "https://api.hackertarget.com/ipgeo/?q={ip}"
_HIBP_DOMAIN         = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"

# Paleta de severidades (colores Rich)
_SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim white",
}

# Orden numérico de severidades
_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


# ---------------------------------------------------------------------------
# Modelos de datos
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity:    str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    source:      str   # nombre de la fuente (ThreatFox, GreyNoise…)
    category:    str   # tipo de hallazgo (C2, Ransomware, Malware…)
    name:        str   # título corto
    detail:      str   # descripción extendida
    remediation: str   # acción recomendada


@dataclass
class TargetResult:
    target:      str
    target_type: str                     # domain | ip | hash | url
    findings:    List[Finding]           = field(default_factory=list)
    raw_sources: Dict[str, object]       = field(default_factory=dict)
    error:       Optional[str]           = None
    scan_time:   str                     = ""

    # ---------- helpers ----------
    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def critical(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]

    def high(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "HIGH"]

    def summary_grade(self) -> str:
        """Riesgo general: CRITICAL > HIGH > MEDIUM > LOW > CLEAN."""
        if self.critical():   return "CRITICAL"
        if self.high():       return "HIGH"
        if any(f.severity == "MEDIUM" for f in self.findings): return "MEDIUM"
        if any(f.severity == "LOW"    for f in self.findings): return "LOW"
        return "CLEAN"

    def risk_color(self) -> str:
        g = self.summary_grade()
        return _SEV_COLOR.get(g, "green")


# ---------------------------------------------------------------------------
# Utilidades de red
# ---------------------------------------------------------------------------

def _get(url: str, headers: Optional[Dict] = None, timeout: int = _TIMEOUT) -> dict | str | None:
    """GET HTTP → JSON o texto plano; None en caso de error."""
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header("User-Agent", f"VampSecure-Labs/{TOOL_NAME}/{VERSION}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            ct   = resp.headers.get("Content-Type", "")
            if "json" in ct:
                return json.loads(body)
            return body
    except Exception:
        return None


def _post_json(url: str, payload: dict, timeout: int = _TIMEOUT) -> dict | None:
    """POST JSON → JSON; None en caso de error."""
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", f"VampSecure-Labs/{TOOL_NAME}/{VERSION}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def _post_form(url: str, fields: Dict[str, str], timeout: int = _TIMEOUT) -> dict | None:
    """POST form-urlencoded → JSON; None en caso de error."""
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", f"VampSecure-Labs/{TOOL_NAME}/{VERSION}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Detección de tipo de objetivo
# ---------------------------------------------------------------------------

_HASH_RE  = re.compile(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$')
_EMAIL_RE = re.compile(r'^[^@]+@[^@]+\.[^@]+$')


def detect_target_type(target: str) -> str:
    """Devuelve 'domain', 'ip', 'hash', 'url' o 'email'."""
    if target.startswith(("http://", "https://")):
        return "url"
    if _EMAIL_RE.match(target):
        return "email"
    if _HASH_RE.match(target):
        return "hash"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass
    return "domain"


# ---------------------------------------------------------------------------
# Fuentes de threat intelligence
# ---------------------------------------------------------------------------

def _source_threatfox(target: str, target_type: str) -> List[Finding]:
    """ThreatFox (abuse.ch) — IOCs por dominio, IP, URL o hash."""
    findings: List[Finding] = []
    payload  = {"query": "search_ioc", "search_term": target}
    data     = _post_json(_THREATFOX_API, payload)
    if not data or data.get("query_status") not in ("ok", "no_result"):
        return findings

    iocs = data.get("data") or []
    if not iocs:
        return findings

    for ioc in iocs[:10]:   # máximo 10 entradas
        threat_type  = ioc.get("threat_type", "")
        malware      = ioc.get("malware", "")
        confidence   = ioc.get("confidence_level", 0)
        last_seen    = ioc.get("last_seen", "")

        if threat_type in ("botnet_cc", "c2"):
            sev  = "CRITICAL"
            name = f"C2/Botnet confirmado ({malware})"
        elif confidence >= 75:
            sev  = "HIGH"
            name = f"IOC en ThreatFox — {threat_type} ({malware})"
        else:
            sev  = "MEDIUM"
            name = f"IOC en ThreatFox — {threat_type} ({malware})"

        findings.append(Finding(
            severity    = sev,
            source      = "ThreatFox",
            category    = "Threat Feed",
            name        = name,
            detail      = (
                f"Tipo de amenaza: {threat_type} · Malware: {malware} · "
                f"Confianza: {confidence}% · Última vez visto: {last_seen}"
            ),
            remediation = "Bloquear la IOC en el perímetro (firewall, DNS sinkhole). "
                          "Investigar sistemas que hayan contactado este indicador.",
        ))

    return findings


def _source_urlhaus(target: str, target_type: str) -> List[Finding]:
    """URLhaus (abuse.ch) — URLs y hosts maliciosos."""
    findings: List[Finding] = []

    if target_type == "url":
        data = _post_form(_URLHAUS_URL_API, {"url": target})
    else:
        data = _post_form(_URLHAUS_HOST_API, {"host": target})

    if not data or data.get("query_status") not in ("ok", "is_host"):
        return findings

    urls = data.get("urls") or []
    active_count = sum(1 for u in urls if u.get("url_status") == "online")
    total_count  = len(urls)

    if total_count == 0:
        return findings

    sev  = "CRITICAL" if active_count > 0 else "HIGH"
    name = (
        f"{'Activo en' if active_count else 'Histórico en'} URLhaus "
        f"({active_count} activas / {total_count} total)"
    )
    findings.append(Finding(
        severity    = sev,
        source      = "URLhaus",
        category    = "Malware Distribution",
        name        = name,
        detail      = (
            f"URLs maliciosas asociadas: {total_count} "
            f"({active_count} actualmente activas)"
        ),
        remediation = "Bloquear dominio/IP en firewall y proxy. "
                      "Notificar usuarios que hayan accedido al host.",
    ))
    return findings


def _source_malwarebazaar(target: str, target_type: str) -> List[Finding]:
    """MalwareBazaar (abuse.ch) — búsqueda por hash."""
    if target_type != "hash":
        return []
    findings: List[Finding] = []
    data = _post_form(_BAZAAR_API, {"query": "get_info", "hash": target})
    if not data or data.get("query_status") != "ok":
        return findings

    samples = data.get("data") or []
    for s in samples[:5]:
        malware   = s.get("signature") or s.get("tags", ["?"])[0]
        file_type = s.get("file_type", "")
        first_seen = s.get("first_seen", "")
        findings.append(Finding(
            severity    = "CRITICAL",
            source      = "MalwareBazaar",
            category    = "Malware",
            name        = f"Hash de malware confirmado ({malware})",
            detail      = (
                f"Tipo: {file_type} · Familia: {malware} · "
                f"Primera vez visto: {first_seen}"
            ),
            remediation = "Aislar inmediatamente cualquier sistema que ejecute este hash. "
                          "Iniciar proceso de respuesta a incidentes.",
        ))
    return findings


def _source_ransomlook(target: str, target_type: str) -> List[Finding]:
    """RansomLook — víctimas de ransomware por dominio o nombre."""
    if target_type not in ("domain", "url"):
        return []

    findings: List[Finding] = []
    domain = target.lower().split("/")[0]
    data   = _get(_RANSOMLOOK_RECENT)

    if not isinstance(data, dict):
        return findings

    # RansomLook devuelve un dict de grupos con listas de posts
    matches: List[Tuple[str, str, str]] = []   # (grupo, descripción, fecha)
    for group_name, posts in data.items():
        if not isinstance(posts, list):
            continue
        for post in posts:
            desc    = str(post.get("description", "") or post.get("post_title", "")).lower()
            website = str(post.get("website", "")).lower()
            title   = str(post.get("post_title", "")).lower()
            date    = post.get("discovered", "") or post.get("date", "")
            base    = domain.replace("www.", "").split(".")[0]
            if base in desc or base in website or domain in website:
                matches.append((group_name, title or desc[:120], date))

    for group, desc, date in matches[:3]:
        findings.append(Finding(
            severity    = "HIGH",
            source      = "RansomLook",
            category    = "Ransomware",
            name        = f"Posible víctima de ransomware — grupo {group}",
            detail      = f"Grupo: {group} · Descripción: {desc[:200]} · Fecha: {date}",
            remediation = "Verificar si la organización fue afectada. "
                          "Revisar logs de EDR/SIEM en las fechas indicadas.",
        ))
    return findings


def _source_ransomwarelive(target: str, target_type: str) -> List[Finding]:
    """Ransomware.live — víctimas recientes por dominio."""
    if target_type not in ("domain", "url"):
        return []

    findings: List[Finding] = []
    domain = target.lower().split("/")[0].replace("www.", "")
    base   = domain.split(".")[0]
    data   = _get(_RANSOMWARELIVE_API)

    if not isinstance(data, list):
        return findings

    for victim in data:
        victim_name    = str(victim.get("victim", "") or "").lower()
        victim_website = str(victim.get("website", "") or "").lower()
        group          = victim.get("group", "?")
        country        = victim.get("country", "?")
        published      = victim.get("published", "")
        if base in victim_name or domain in victim_website:
            findings.append(Finding(
                severity    = "HIGH",
                source      = "Ransomware.live",
                category    = "Ransomware",
                name        = f"Víctima confirmada en Ransomware.live — {group}",
                detail      = (
                    f"Grupo: {group} · País: {country} · "
                    f"Publicado: {published} · Web: {victim_website}"
                ),
                remediation = "Verificar alcance real del incidente. "
                              "Contactar con la organización si procede.",
            ))
    return findings


def _source_greynoise(target: str, target_type: str) -> List[Finding]:
    """GreyNoise Community — contexto de IP (sin clave API)."""
    if target_type != "ip":
        return []

    findings: List[Finding] = []
    data = _get(_GREYNOISE_COMM.format(ip=target))

    if not isinstance(data, dict):
        return findings

    noise         = data.get("noise", False)
    riot          = data.get("riot", False)
    classification = data.get("classification", "unknown")
    name          = data.get("name", "")
    last_seen     = data.get("last_seen", "")

    if riot:
        findings.append(Finding(
            severity    = "INFO",
            source      = "GreyNoise",
            category    = "IP Context",
            name        = f"IP de infraestructura legítima conocida ({name})",
            detail      = f"RIOT: proveedor o infraestructura benigna — {name}",
            remediation = "Sin acción requerida.",
        ))
        return findings

    if classification == "malicious":
        findings.append(Finding(
            severity    = "HIGH",
            source      = "GreyNoise",
            category    = "Malicious IP",
            name        = f"IP clasificada como maliciosa en GreyNoise ({name or target})",
            detail      = (
                f"Clasificación: {classification} · Noise: {noise} · "
                f"Última actividad: {last_seen}"
            ),
            remediation = "Bloquear IP en firewall perimetral. "
                          "Revisar logs para detectar conexiones previas.",
        ))
    elif noise:
        findings.append(Finding(
            severity    = "MEDIUM",
            source      = "GreyNoise",
            category    = "Scanner",
            name        = "IP activa en internet scanning (GreyNoise)",
            detail      = (
                f"Clasificación: {classification} · Nombre: {name} · "
                f"Última actividad: {last_seen}"
            ),
            remediation = "Valorar bloqueo proactivo si no hay relación de negocio.",
        ))
    return findings


def _source_shodan_internetdb(target: str, target_type: str) -> List[Finding]:
    """Shodan InternetDB — puertos, etiquetas y CVEs de IP (sin auth)."""
    if target_type != "ip":
        return []

    findings: List[Finding] = []
    data = _get(_SHODAN_INTERNETDB.format(ip=target))

    if not isinstance(data, dict) or "ip" not in data:
        return findings

    vulns = data.get("vulns") or []
    tags  = data.get("tags") or []
    ports = data.get("open_ports") or []

    if vulns:
        sev  = "CRITICAL" if any("critical" in v.lower() for v in vulns) else "HIGH"
        findings.append(Finding(
            severity    = sev,
            source      = "Shodan InternetDB",
            category    = "Vulnerabilidades",
            name        = f"CVEs conocidos en IP: {', '.join(vulns[:5])}",
            detail      = (
                f"CVEs: {', '.join(vulns)} · "
                f"Puertos abiertos: {', '.join(str(p) for p in ports[:10])}"
            ),
            remediation = "Aplicar parches o mitigaciones para los CVEs listados. "
                          "Revisar si los puertos abiertos son necesarios.",
        ))
    elif ports:
        findings.append(Finding(
            severity    = "LOW",
            source      = "Shodan InternetDB",
            category    = "Surface de ataque",
            name        = f"Puertos abiertos detectados: {', '.join(str(p) for p in ports[:8])}",
            detail      = f"Tags: {', '.join(tags)} · Puertos: {', '.join(str(p) for p in ports)}",
            remediation = "Revisar que los servicios expuestos sean intencionales.",
        ))

    if "honeypot" in tags:
        findings.append(Finding(
            severity    = "INFO",
            source      = "Shodan InternetDB",
            category    = "Honeypot",
            name        = "IP identificada como honeypot (Shodan)",
            detail      = "Shodan ha etiquetado esta IP como honeypot.",
            remediation = "Sin acción requerida, pero evitar conectarse a ella.",
        ))
    return findings


def _source_otx(target: str, target_type: str) -> List[Finding]:
    """AlienVault OTX — pulsos de inteligencia."""
    findings: List[Finding] = []

    api_key = os.getenv("OTX_API_KEY", "")
    headers  = {"X-OTX-API-KEY": api_key} if api_key else {}

    if target_type == "domain":
        url = _OTX_DOMAIN.format(target=target)
    elif target_type == "ip":
        url = _OTX_IP.format(target=target)
    elif target_type == "hash":
        url = _OTX_HASH.format(target=target)
    else:
        return findings

    data = _get(url, headers=headers)
    if not isinstance(data, dict):
        return findings

    pulse_count    = data.get("pulse_info", {}).get("count", 0)
    validation     = data.get("validation", [])
    is_whitelisted = any(v.get("source") == "whitelist" for v in validation)

    if is_whitelisted:
        return findings

    if pulse_count >= 10:
        sev = "HIGH"
    elif pulse_count >= 3:
        sev = "MEDIUM"
    elif pulse_count >= 1:
        sev = "LOW"
    else:
        return findings

    findings.append(Finding(
        severity    = sev,
        source      = "AlienVault OTX",
        category    = "Threat Intelligence",
        name        = f"Presente en {pulse_count} pulso(s) de inteligencia (OTX)",
        detail      = (
            f"Pulsos: {pulse_count} · Indicador: {target}"
        ),
        remediation = "Revisar los pulsos OTX para contexto adicional: "
                      "https://otx.alienvault.com",
    ))
    return findings


def _source_hackertarget_geo(target: str, target_type: str) -> List[Finding]:
    """HackerTarget — geolocalización de IP (contexto INFO)."""
    if target_type != "ip":
        return []
    findings: List[Finding] = []
    raw = _get(_HACKERTARGET_GEO.format(ip=target))
    if not isinstance(raw, str) or "error" in raw.lower():
        return findings
    findings.append(Finding(
        severity    = "INFO",
        source      = "HackerTarget",
        category    = "Geolocalización",
        name        = "Datos geográficos de IP",
        detail      = raw.strip().replace("\n", " · "),
        remediation = "",
    ))
    return findings


def _source_hibp(target: str, target_type: str) -> List[Finding]:
    """Have I Been Pwned — brechas de dominio (requiere HIBP_API_KEY)."""
    if target_type != "domain":
        return []
    api_key = os.getenv("HIBP_API_KEY", "")
    if not api_key:
        return []
    findings: List[Finding] = []
    url  = _HIBP_DOMAIN.format(domain=target)
    data = _get(url, headers={"hibp-api-key": api_key, "user-agent": f"vamp-darkweb-intel/{VERSION}"})
    if not isinstance(data, dict):
        return findings
    breaches = list(data.keys())
    if breaches:
        findings.append(Finding(
            severity    = "HIGH",
            source      = "HIBP",
            category    = "Breach",
            name        = f"Dominio presente en {len(breaches)} brecha(s) conocida(s)",
            detail      = f"Brechas: {', '.join(breaches[:10])}",
            remediation = "Forzar cambio de contraseñas para cuentas del dominio afectado. "
                          "Revisar si se expusieron otros datos sensibles.",
        ))
    return findings


# ---------------------------------------------------------------------------
# Motor de correlación
# ---------------------------------------------------------------------------

def _correlate(findings: List[Finding]) -> List[Finding]:
    """
    Escala severidad de hallazgos duplicados entre fuentes.
    Si una IOC aparece en ≥2 fuentes independientes, el hallazgo de mayor
    severidad sube un nivel (max: CRITICAL).
    """
    categories: Dict[str, List[Finding]] = {}
    for f in findings:
        key = f.category
        categories.setdefault(key, []).append(f)

    upgraded: List[Finding] = []
    for cat_findings in categories.values():
        # Fuentes únicas que reportan esta categoría
        sources = {f.source for f in cat_findings}
        if len(sources) >= 2:
            # El hallazgo de mayor severidad sube un nivel
            ranked = sorted(cat_findings, key=lambda x: _SEV_RANK.get(x.severity, 0), reverse=True)
            top = ranked[0]
            levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            current_idx = levels.index(top.severity) if top.severity in levels else 0
            new_sev = levels[min(current_idx + 1, 4)]
            if new_sev != top.severity:
                upgraded.append(Finding(
                    severity    = new_sev,
                    source      = "Correlación",
                    category    = cat_findings[0].category,
                    name        = f"Señal multi-fuente: {top.name}",
                    detail      = (
                        f"Detectado en {len(sources)} fuentes independientes: "
                        f"{', '.join(sorted(sources))}. Severidad escalada de "
                        f"{top.severity} a {new_sev}."
                    ),
                    remediation = top.remediation,
                ))

    return findings + upgraded


# ---------------------------------------------------------------------------
# Motor principal
# ---------------------------------------------------------------------------

# Mapeo fuente → función
_ALL_SOURCES = [
    _source_threatfox,
    _source_urlhaus,
    _source_malwarebazaar,
    _source_ransomlook,
    _source_ransomwarelive,
    _source_greynoise,
    _source_shodan_internetdb,
    _source_otx,
    _source_hackertarget_geo,
    _source_hibp,
]


class DarkwebIntelEngine:
    """Orquesta la consulta paralela a todas las fuentes y genera TargetResult."""

    def __init__(self, timeout: int = _TIMEOUT, workers: int = 6) -> None:
        self._timeout = timeout
        self._workers = workers

    def scan(self, target: str, target_type: Optional[str] = None) -> TargetResult:
        target      = target.strip()
        target_type = target_type or detect_target_type(target)
        result      = TargetResult(
            target      = target,
            target_type = target_type,
            scan_time   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

        all_findings: List[Finding] = []

        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            futures = {pool.submit(fn, target, target_type): fn.__name__ for fn in _ALL_SOURCES}
            for fut in as_completed(futures):
                try:
                    findings = fut.result(timeout=self._timeout + 2)
                    all_findings.extend(findings)
                except Exception:
                    pass

        # Correlacionar y ordenar por severidad
        all_findings = _correlate(all_findings)
        all_findings.sort(key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
        result.findings = all_findings

        return result


# ---------------------------------------------------------------------------
# Salida por consola (Rich)
# ---------------------------------------------------------------------------

_console = Console()


def _print_result(result: TargetResult) -> None:
    grade      = result.summary_grade()
    grade_color = result.risk_color()

    # Cabecera
    _console.rule(f"[bold]{result.target}[/bold] — [italic]{result.target_type}[/italic]")

    grade_text = f"[{grade_color}]{grade}[/{grade_color}]"
    _console.print(
        f"  Nivel de riesgo: {grade_text}  ·  "
        f"Hallazgos: {len(result.findings)}  ·  "
        f"Escaneado: {result.scan_time}",
    )

    if not result.findings:
        _console.print("  [green]Sin hallazgos en fuentes consultadas.[/green]\n")
        return

    tbl = Table(
        "SEV", "Fuente", "Categoría", "Hallazgo", "Detalle",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold white",
    )

    for f in result.findings:
        color = _SEV_COLOR.get(f.severity, "white")
        tbl.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.source,
            f.category,
            f.name,
            f.detail[:120] + ("…" if len(f.detail) > 120 else ""),
        )

    _console.print(tbl)
    _console.print()


# ---------------------------------------------------------------------------
# Exportadores
# ---------------------------------------------------------------------------

def _to_json(results: List[TargetResult]) -> str:
    def _finding_dict(f: Finding) -> dict:
        return {
            "severity": f.severity, "source": f.source, "category": f.category,
            "name": f.name, "detail": f.detail, "remediation": f.remediation,
        }
    out = []
    for r in results:
        out.append({
            "target": r.target,
            "target_type": r.target_type,
            "risk_grade": r.summary_grade(),
            "scan_time": r.scan_time,
            "findings": [_finding_dict(f) for f in r.findings],
        })
    return json.dumps(out, indent=2, ensure_ascii=False)


def _to_markdown(results: List[TargetResult]) -> str:
    lines: List[str] = [
        "# vamp-darkweb-intel — Informe de Threat Intelligence",
        "",
        f"Generado: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"Herramienta: {TOOL_NAME} v{VERSION}",
        "",
        "---",
        "",
    ]
    for r in results:
        lines += [
            f"## {r.target} ({r.target_type})",
            "",
            f"**Nivel de riesgo:** {r.summary_grade()}  ",
            f"**Hallazgos:** {len(r.findings)}  ",
            f"**Escaneado:** {r.scan_time}",
            "",
        ]
        if not r.findings:
            lines += ["Sin hallazgos en fuentes consultadas.", ""]
            continue

        lines += [
            "| Severidad | Fuente | Categoría | Hallazgo |",
            "|-----------|--------|-----------|----------|",
        ]
        for f in r.findings:
            lines.append(f"| {f.severity} | {f.source} | {f.category} | {f.name} |")

        lines += [""]
        for f in r.findings:
            if f.remediation:
                lines += [
                    f"**{f.name}**  ",
                    f"Detalle: {f.detail}  ",
                    f"Remediación: {f.remediation}",
                    "",
                ]
        lines += ["---", ""]

    return "\n".join(lines)


def _to_csv(results: List[TargetResult]) -> str:
    import io
    buf  = io.StringIO()
    w    = csv.writer(buf)
    w.writerow(["target", "target_type", "risk_grade", "severity", "source",
                "category", "name", "detail", "remediation"])
    for r in results:
        for f in r.findings:
            w.writerow([
                r.target, r.target_type, r.summary_grade(),
                f.severity, f.source, f.category, f.name, f.detail, f.remediation,
            ])
    return buf.getvalue()


def _to_html(results: List[TargetResult]) -> str:
    """Informe HTML dark-theme standalone."""
    rows_html = ""
    for r in results:
        grade       = r.summary_grade()
        grade_colors = {
            "CRITICAL": "#ff4444", "HIGH": "#ff8800",
            "MEDIUM": "#ffcc00", "LOW": "#44aaff", "CLEAN": "#44cc44",
        }
        gc = grade_colors.get(grade, "#888")

        rows_html += f"""
        <div class="target-block">
          <div class="target-header">
            <span class="target-name">{r.target}</span>
            <span class="target-type">{r.target_type}</span>
            <span class="risk-badge" style="background:{gc}">{grade}</span>
            <span class="meta">{r.scan_time} · {len(r.findings)} hallazgos</span>
          </div>
"""
        if r.findings:
            rows_html += """
          <table class="findings-table">
            <thead><tr><th>SEV</th><th>Fuente</th><th>Categoría</th>
              <th>Hallazgo</th><th>Detalle</th></tr></thead><tbody>
"""
            sev_colors = {
                "CRITICAL": "#ff4444", "HIGH": "#ff8800",
                "MEDIUM": "#ffcc00", "LOW": "#44aaff", "INFO": "#888888",
            }
            for f in r.findings:
                sc = sev_colors.get(f.severity, "#888")
                rows_html += f"""
            <tr>
              <td><span class="sev-tag" style="color:{sc}">{f.severity}</span></td>
              <td>{f.source}</td>
              <td>{f.category}</td>
              <td>{f.name}</td>
              <td class="detail-col">{f.detail[:200]}</td>
            </tr>
"""
            rows_html += "</tbody></table>"
        else:
            rows_html += '<p class="clean-msg">Sin hallazgos en fuentes consultadas.</p>'

        rows_html += "</div>"

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>vamp-darkweb-intel — Informe</title>
<style>
  body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',Helvetica,Arial,sans-serif;margin:0;padding:20px}}
  h1{{color:#58a6ff;font-size:1.4rem;margin-bottom:4px}}
  .meta-header{{color:#8b949e;font-size:.85rem;margin-bottom:24px}}
  .target-block{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:20px}}
  .target-header{{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}}
  .target-name{{font-size:1.1rem;font-weight:700;color:#e6edf3}}
  .target-type{{background:#21262d;color:#8b949e;border-radius:4px;padding:2px 8px;font-size:.78rem}}
  .risk-badge{{border-radius:4px;padding:3px 10px;font-size:.82rem;font-weight:700;color:#0d1117}}
  .meta{{color:#8b949e;font-size:.8rem;margin-left:auto}}
  .findings-table{{width:100%;border-collapse:collapse;font-size:.84rem;margin-top:8px}}
  .findings-table th{{background:#21262d;color:#8b949e;text-align:left;padding:8px;border-bottom:1px solid #30363d}}
  .findings-table td{{padding:8px;border-bottom:1px solid #21262d;vertical-align:top}}
  .findings-table tr:hover td{{background:#1c2128}}
  .sev-tag{{font-weight:700}}
  .detail-col{{color:#8b949e;font-size:.8rem}}
  .clean-msg{{color:#3fb950;font-size:.9rem;margin:8px 0}}
  footer{{margin-top:32px;color:#484f58;font-size:.78rem;text-align:center}}
</style>
</head>
<body>
<h1>vamp-darkweb-intel — Informe de Threat Intelligence</h1>
<p class="meta-header">Generado: {ts} · Herramienta: {TOOL_NAME} v{VERSION} · VampSecure Labs</p>
{rows_html}
<footer>© VampSecure Studios — VampSecure Labs Security Research Division | Uso exclusivo en entornos autorizados</footer>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vamp-darkweb-intel",
        description=(
            "vamp-darkweb-intel — Motor de Threat Intelligence y Darkweb\n"
            "VampSecure Labs · Consulta cruzada multi-fuente con correlación automática"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-t", "--target",
                   metavar="TARGET", action="append", dest="targets", default=[],
                   help="Objetivo a investigar: dominio, IP, hash (MD5/SHA1/SHA256) o URL. "
                        "Repetible para múltiples objetivos.")
    p.add_argument("--file",
                   metavar="FILE",
                   help="Fichero con un objetivo por línea.")
    p.add_argument("--type",
                   choices=["domain", "ip", "hash", "url", "email"],
                   help="Forzar tipo de objetivo (por defecto: autodetectado).")
    p.add_argument("--timeout", type=int, default=12, metavar="N",
                   help="Timeout por petición en segundos (default: 12).")
    p.add_argument("--workers", type=int, default=6, metavar="N",
                   help="Consultas paralelas a fuentes (default: 6).")
    p.add_argument("--json",  metavar="FILE", dest="out_json",
                   help="Exportar resultados a JSON.")
    p.add_argument("--html",  metavar="FILE", dest="out_html",
                   help="Exportar informe HTML dark-theme.")
    p.add_argument("--markdown", metavar="FILE", dest="out_md",
                   help="Exportar informe Markdown.")
    p.add_argument("--csv",  metavar="FILE", dest="out_csv",
                   help="Exportar resumen CSV.")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main() -> None:
    p    = _build_parser()
    args = p.parse_args()

    # Recoger objetivos
    targets: List[str] = list(args.targets)
    if args.file:
        fp = Path(args.file) if 'Path' in dir() else __import__('pathlib').Path(args.file)
        targets += [l.strip() for l in fp.read_text().splitlines() if l.strip() and not l.startswith("#")]

    if not targets:
        p.print_help()
        sys.exit(0)

    engine  = DarkwebIntelEngine(timeout=args.timeout, workers=args.workers)
    results: List[TargetResult] = []

    for target in targets:
        result = engine.scan(target, args.type)
        results.append(result)
        _print_result(result)

    # Exportar
    if args.out_json:
        Path(args.out_json).write_text(_to_json(results), encoding="utf-8")
        _console.print(f"[dim]→ JSON: {args.out_json}[/dim]")
    if args.out_md:
        Path(args.out_md).write_text(_to_markdown(results), encoding="utf-8")
        _console.print(f"[dim]→ Markdown: {args.out_md}[/dim]")
    if args.out_csv:
        Path(args.out_csv).write_text(_to_csv(results), encoding="utf-8")
        _console.print(f"[dim]→ CSV: {args.out_csv}[/dim]")
    if args.out_html:
        Path(args.out_html).write_text(_to_html(results), encoding="utf-8")
        _console.print(f"[dim]→ HTML: {args.out_html}[/dim]")

    # Código de salida
    has_critical = any(r.critical() for r in results)
    has_high     = any(r.high() for r in results)
    if has_critical:
        sys.exit(2)
    elif has_high:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    from pathlib import Path
    main()
