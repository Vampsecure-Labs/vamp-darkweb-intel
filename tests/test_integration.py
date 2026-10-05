# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests de integración para vamp-darkweb-intel."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytestmark = pytest.mark.integration

# Parchear dependencias Rich antes de importar el módulo principal
with patch.dict("sys.modules", {
    "rich": MagicMock(),
    "rich.console": MagicMock(),
    "rich.panel": MagicMock(),
    "rich.table": MagicMock(),
    "rich.box": MagicMock(),
}):
    import vamp_darkweb_intel as vdi


# ── Test 1: Flujo ThreatFox + URLhaus combinados ─────────────────────────────

def test_flujo_threatfox_mas_urlhaus_acumulan_findings(
    ip_objetivo,
    respuesta_threatfox_positivo,
    respuesta_urlhaus_activo,
):
    """
    Verifica que al llamar a ThreatFox y URLhaus sobre la misma IP
    los hallazgos se acumulan correctamente y el grado es CRITICAL.
    """
    result = vdi.TargetResult(target=ip_objetivo, target_type="ip")

    with patch.object(vdi, "_post_json", return_value=respuesta_threatfox_positivo):
        findings_tf = vdi._source_threatfox(ip_objetivo, "ip")

    with patch.object(vdi, "_post_form", return_value=respuesta_urlhaus_activo):
        findings_uh = vdi._source_urlhaus(ip_objetivo, "ip")

    for f in findings_tf + findings_uh:
        result.add(f)

    # Debe haber hallazgos de ambas fuentes
    fuentes = {f.source for f in result.findings}
    assert "ThreatFox" in fuentes
    assert "URLhaus" in fuentes

    # El grado global debe ser CRITICAL (hay un botnet_cc de ThreatFox)
    assert result.summary_grade() == "CRITICAL"


# ── Test 2: Flujo GreyNoise + Shodan InternetDB sobre una IP ──────────────────

def test_flujo_greynoise_mas_shodan_ip(
    ip_objetivo,
    respuesta_greynoise_malicioso,
    respuesta_shodan_internetdb,
):
    """
    Simula la consulta de GreyNoise y Shodan InternetDB sobre una misma IP
    y verifica que los hallazgos de ambas fuentes se integran en TargetResult.
    """
    result = vdi.TargetResult(target=ip_objetivo, target_type="ip")

    with patch.object(vdi, "_get", side_effect=[
        respuesta_greynoise_malicioso,
        respuesta_shodan_internetdb,
    ]):
        findings_gn = vdi._source_greynoise(ip_objetivo, "ip")
        findings_sh = vdi._source_shodan_internetdb(ip_objetivo, "ip")

    for f in findings_gn + findings_sh:
        result.add(f)

    fuentes = {f.source for f in result.findings}
    assert "GreyNoise" in fuentes
    assert "Shodan InternetDB" in fuentes
    # Con IP maliciosa + CVEs, el grado debe ser al menos HIGH
    assert result.summary_grade() in ("CRITICAL", "HIGH")


# ── Test 3: Flujo MalwareBazaar para un hash ──────────────────────────────────

def test_flujo_malwarebazaar_hash_detectado(hash_objetivo, respuesta_bazaar_hash):
    """
    Verifica que al escanear un hash, MalwareBazaar genera un Finding CRITICAL
    y que el TargetResult refleja el grado adecuado.
    """
    result = vdi.TargetResult(target=hash_objetivo, target_type="hash")

    with patch.object(vdi, "_post_form", return_value=respuesta_bazaar_hash):
        findings = vdi._source_malwarebazaar(hash_objetivo, "hash")

    for f in findings:
        result.add(f)

    assert result.summary_grade() == "CRITICAL"
    assert result.findings[0].category == "Malware"
    assert "Emotet" in result.findings[0].name


# ── Test 4: RansomLook detecta víctima de ransomware ─────────────────────────

def test_flujo_ransomlook_victima_detectada(
    dominio_objetivo,
    respuesta_ransomlook,
):
    """
    Verifica que RansomLook identifica correctamente al dominio como víctima
    de ransomware cuando aparece en la lista de posts recientes.
    """
    result = vdi.TargetResult(target=dominio_objetivo, target_type="domain")

    with patch.object(vdi, "_get", return_value=respuesta_ransomlook):
        findings = vdi._source_ransomlook(dominio_objetivo, "domain")

    for f in findings:
        result.add(f)

    # Debe haberse detectado al menos un hallazgo de ransomware
    assert len(findings) >= 1
    assert findings[0].source == "RansomLook"
    assert findings[0].severity == "HIGH"
    assert findings[0].category == "Ransomware"


# ── Test 5: TargetResult con múltiples fuentes → risk_color y serialización ───

def test_target_result_serializable_y_risk_color():
    """
    Verifica que TargetResult es serializable a dict y que risk_color()
    devuelve un color coherente con el grado de riesgo calculado.
    """
    result = vdi.TargetResult(
        target="1.2.3.4",
        target_type="ip",
        scan_time="2026-10-05T10:00:00Z",
    )
    result.add(vdi.Finding(
        severity="HIGH", source="GreyNoise",
        category="Malicious IP", name="IP maliciosa",
        detail="clasificación: malicious", remediation="bloquear"
    ))
    result.add(vdi.Finding(
        severity="LOW", source="Shodan InternetDB",
        category="Surface de ataque", name="Puertos abiertos",
        detail="puertos: 22,80,443", remediation="revisar"
    ))

    grado = result.summary_grade()
    color = result.risk_color()

    assert grado == "HIGH"
    # El color de HIGH no debe ser el de CLEAN (verde)
    assert color != "green"
    # Verificar que los datos básicos están presentes
    assert result.target == "1.2.3.4"
    assert result.target_type == "ip"
    assert len(result.findings) == 2
    assert len(result.critical()) == 0
    assert len(result.high()) == 1
