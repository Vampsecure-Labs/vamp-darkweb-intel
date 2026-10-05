# © VampSecure Studios — VampSecure Labs Security Research Division
"""Fixtures compartidas para los tests de vamp-darkweb-intel."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def ip_objetivo():
    """IP objetivo para tests de fuentes que requieren IP."""
    return "185.130.5.200"


@pytest.fixture
def dominio_objetivo():
    """Dominio objetivo para tests de fuentes que requieren dominio."""
    return "empresa-victima.com"


@pytest.fixture
def hash_objetivo():
    """Hash MD5 de malware para tests de MalwareBazaar."""
    return "d41d8cd98f00b204e9800998ecf8427e"


@pytest.fixture
def respuesta_threatfox_positivo():
    """Respuesta simulada de ThreatFox con IOC confirmado."""
    return {
        "query_status": "ok",
        "data": [
            {
                "id": "1234567",
                "ioc": "185.130.5.200",
                "threat_type": "botnet_cc",
                "malware": "Emotet",
                "confidence_level": 90,
                "last_seen": "2026-09-15",
                "tags": ["emotet", "banking"],
            },
            {
                "id": "1234568",
                "ioc": "185.130.5.200",
                "threat_type": "payload_delivery",
                "malware": "TrickBot",
                "confidence_level": 75,
                "last_seen": "2026-09-10",
                "tags": [],
            },
        ],
    }


@pytest.fixture
def respuesta_threatfox_sin_resultados():
    """Respuesta simulada de ThreatFox sin IOCs."""
    return {
        "query_status": "no_result",
        "data": [],
    }


@pytest.fixture
def respuesta_urlhaus_activo():
    """Respuesta simulada de URLhaus con URLs activas."""
    return {
        "query_status": "is_host",
        "urls": [
            {"url_status": "online", "url": "http://185.130.5.200/mal.exe"},
            {"url_status": "offline", "url": "http://185.130.5.200/old.exe"},
            {"url_status": "online", "url": "http://185.130.5.200/payload.zip"},
        ],
    }


@pytest.fixture
def respuesta_urlhaus_sin_resultados():
    """Respuesta simulada de URLhaus sin URLs."""
    return {"query_status": "no_results"}


@pytest.fixture
def respuesta_greynoise_malicioso():
    """Respuesta simulada de GreyNoise con IP clasificada como maliciosa."""
    return {
        "ip": "185.130.5.200",
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "Emotet C2",
        "last_seen": "2026-09-15",
    }


@pytest.fixture
def respuesta_greynoise_riot():
    """Respuesta simulada de GreyNoise con IP RIOT (infraestructura legítima)."""
    return {
        "ip": "8.8.8.8",
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Google DNS",
        "last_seen": "2026-10-01",
    }


@pytest.fixture
def respuesta_shodan_internetdb():
    """Respuesta simulada de Shodan InternetDB."""
    return {
        "ip": "185.130.5.200",
        "open_ports": [22, 80, 443, 6379],
        "vulns": ["CVE-2024-1234", "CVE-2023-5678"],
        "tags": ["database", "self-signed"],
        "cpes": [],
    }


@pytest.fixture
def respuesta_bazaar_hash():
    """Respuesta simulada de MalwareBazaar para un hash."""
    return {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "abc123def456",
                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                "file_type": "exe",
                "signature": "Emotet",
                "tags": ["emotet"],
                "first_seen": "2026-08-01",
            },
        ],
    }


@pytest.fixture
def respuesta_ransomlook():
    """Respuesta simulada de RansomLook con víctima de ransomware."""
    return {
        "LockBit": [
            {
                "post_title": "empresa-victima data leak",
                "description": "empresa-victima.com confidential files leaked",
                "website": "empresa-victima.com",
                "discovered": "2026-09-20",
            },
        ],
        "ALPHV": [],
    }
