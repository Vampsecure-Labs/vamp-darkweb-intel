# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests unitarios para vamp-darkweb-intel."""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Parchear dependencias Rich antes de importar el módulo principal
with patch.dict("sys.modules", {
    "rich": MagicMock(),
    "rich.console": MagicMock(),
    "rich.panel": MagicMock(),
    "rich.table": MagicMock(),
    "rich.box": MagicMock(),
}):
    import vamp_darkweb_intel as vdi


# ── Tests para detect_target_type ────────────────────────────────────────────

class TestDetectTargetType:
    """Pruebas para la función de detección automática del tipo de objetivo."""

    def test_url_http_detectada(self):
        """Una URL que empieza por http:// debe clasificarse como 'url'."""
        assert vdi.detect_target_type("http://malware.ejemplo.com/payload") == "url"

    def test_url_https_detectada(self):
        """Una URL que empieza por https:// debe clasificarse como 'url'."""
        assert vdi.detect_target_type("https://c2.malicioso.ru/cmd") == "url"

    def test_email_detectado(self):
        """Una dirección de email debe clasificarse como 'email'."""
        assert vdi.detect_target_type("victima@empresa.com") == "email"

    def test_hash_md5_detectado(self):
        """Un hash de 32 caracteres hex debe clasificarse como 'hash'."""
        assert vdi.detect_target_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_hash_sha1_detectado(self):
        """Un hash de 40 caracteres hex debe clasificarse como 'hash'."""
        assert vdi.detect_target_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"

    def test_hash_sha256_detectado(self):
        """Un hash de 64 caracteres hex debe clasificarse como 'hash'."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert vdi.detect_target_type(sha256) == "hash"

    def test_ip_ipv4_detectada(self):
        """Una dirección IPv4 válida debe clasificarse como 'ip'."""
        assert vdi.detect_target_type("185.130.5.200") == "ip"

    def test_dominio_detectado(self):
        """Un nombre de dominio debe clasificarse como 'domain'."""
        assert vdi.detect_target_type("empresa-victima.com") == "domain"

    def test_subdominio_detectado_como_dominio(self):
        """Un subdominio debe clasificarse como 'domain'."""
        assert vdi.detect_target_type("api.empresa-victima.com") == "domain"


# ── Tests para _SEV_RANK ──────────────────────────────────────────────────────

class TestSevRank:
    """Pruebas para la tabla de ordenación de severidades."""

    def test_critical_es_el_mas_alto(self):
        """CRITICAL debe tener el rango más alto (5)."""
        assert vdi._SEV_RANK["CRITICAL"] == 5

    def test_info_es_el_mas_bajo(self):
        """INFO debe tener el rango más bajo (1)."""
        assert vdi._SEV_RANK["INFO"] == 1

    def test_orden_de_severidades(self):
        """El orden de severidad debe ser CRITICAL > HIGH > MEDIUM > LOW > INFO."""
        assert (
            vdi._SEV_RANK["CRITICAL"] >
            vdi._SEV_RANK["HIGH"] >
            vdi._SEV_RANK["MEDIUM"] >
            vdi._SEV_RANK["LOW"] >
            vdi._SEV_RANK["INFO"]
        )


# ── Tests para TargetResult.summary_grade ────────────────────────────────────

class TestTargetResultSummaryGrade:
    """Pruebas para el cálculo del grado de riesgo global."""

    def test_sin_findings_devuelve_clean(self):
        """Sin hallazgos, el grado de riesgo debe ser CLEAN."""
        r = vdi.TargetResult(target="ejemplo.com", target_type="domain")
        assert r.summary_grade() == "CLEAN"

    def test_un_finding_critical_devuelve_critical(self):
        """Un hallazgo CRITICAL debe elevar el grado a CRITICAL."""
        r = vdi.TargetResult(target="ejemplo.com", target_type="domain")
        r.add(vdi.Finding(
            severity="CRITICAL", source="ThreatFox",
            category="C2", name="C2 detectado",
            detail="detalle", remediation="bloquear"
        ))
        assert r.summary_grade() == "CRITICAL"

    def test_solo_high_devuelve_high(self):
        """Solo hallazgos HIGH deben dar grado HIGH."""
        r = vdi.TargetResult(target="ejemplo.com", target_type="domain")
        r.add(vdi.Finding(
            severity="HIGH", source="GreyNoise",
            category="Malicious IP", name="IP maliciosa",
            detail="detalle", remediation="bloquear"
        ))
        assert r.summary_grade() == "HIGH"

    def test_solo_medium_devuelve_medium(self):
        """Solo hallazgos MEDIUM deben dar grado MEDIUM."""
        r = vdi.TargetResult(target="1.1.1.1", target_type="ip")
        r.add(vdi.Finding(
            severity="MEDIUM", source="GreyNoise",
            category="Scanner", name="IP escaneadora",
            detail="detalle", remediation="valorar bloqueo"
        ))
        assert r.summary_grade() == "MEDIUM"

    def test_critical_prevalece_sobre_low(self):
        """CRITICAL debe prevalecer aunque haya también hallazgos LOW."""
        r = vdi.TargetResult(target="ejemplo.com", target_type="domain")
        r.add(vdi.Finding(
            severity="LOW", source="Shodan", category="Surface",
            name="Puertos", detail="detalle", remediation="revisar"
        ))
        r.add(vdi.Finding(
            severity="CRITICAL", source="ThreatFox", category="C2",
            name="C2", detail="detalle", remediation="bloquear"
        ))
        assert r.summary_grade() == "CRITICAL"


# ── Tests para TargetResult.critical / high ───────────────────────────────────

class TestTargetResultFiltros:
    """Pruebas para los métodos de filtrado por severidad."""

    def test_critical_filtra_correctamente(self):
        """critical() debe devolver solo los hallazgos CRITICAL."""
        r = vdi.TargetResult(target="ejemplo.com", target_type="domain")
        r.add(vdi.Finding("CRITICAL", "Src", "Cat", "Nombre", "det", "rem"))
        r.add(vdi.Finding("HIGH", "Src", "Cat", "Nombre2", "det", "rem"))
        criticos = r.critical()
        assert len(criticos) == 1
        assert criticos[0].severity == "CRITICAL"

    def test_high_filtra_correctamente(self):
        """high() debe devolver solo los hallazgos HIGH."""
        r = vdi.TargetResult(target="1.2.3.4", target_type="ip")
        r.add(vdi.Finding("HIGH", "GN", "Malicious IP", "IP maliciosa", "det", "rem"))
        r.add(vdi.Finding("INFO", "GN", "Context", "RIOT", "det", "rem"))
        altos = r.high()
        assert len(altos) == 1
        assert altos[0].severity == "HIGH"


# ── Tests para _source_greynoise ─────────────────────────────────────────────

class TestSourceGreyNoise:
    """Pruebas para la fuente GreyNoise Community."""

    def test_ip_maliciosa_genera_finding_high(self, respuesta_greynoise_malicioso):
        """Una IP clasificada como maliciosa debe generar un hallazgo HIGH."""
        with patch.object(vdi, "_get", return_value=respuesta_greynoise_malicioso):
            findings = vdi._source_greynoise("185.130.5.200", "ip")

        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert findings[0].source == "GreyNoise"
        assert "malicious" in findings[0].detail.lower()

    def test_ip_riot_genera_finding_info(self, respuesta_greynoise_riot):
        """Una IP RIOT debe generar un hallazgo INFO (benigna)."""
        with patch.object(vdi, "_get", return_value=respuesta_greynoise_riot):
            findings = vdi._source_greynoise("8.8.8.8", "ip")

        assert len(findings) == 1
        assert findings[0].severity == "INFO"
        assert findings[0].source == "GreyNoise"

    def test_tipo_no_ip_devuelve_lista_vacia(self):
        """Para objetivos que no son IPs, GreyNoise debe devolver lista vacía."""
        findings = vdi._source_greynoise("empresa.com", "domain")
        assert findings == []

    def test_respuesta_none_devuelve_lista_vacia(self):
        """Si _get devuelve None, debe devolverse lista vacía sin excepciones."""
        with patch("vamp_darkweb_intel._get", return_value=None):
            findings = vdi._source_greynoise("185.130.5.200", "ip")
        assert findings == []


# ── Tests para _source_urlhaus ────────────────────────────────────────────────

class TestSourceURLhaus:
    """Pruebas para la fuente URLhaus."""

    def test_urls_activas_generan_finding_critical(self, respuesta_urlhaus_activo):
        """URLs activas en URLhaus deben generar un hallazgo CRITICAL."""
        with patch.object(vdi, "_post_form", return_value=respuesta_urlhaus_activo):
            findings = vdi._source_urlhaus("185.130.5.200", "ip")

        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"
        assert findings[0].source == "URLhaus"

    def test_sin_resultados_devuelve_lista_vacia(self, respuesta_urlhaus_sin_resultados):
        """Respuesta sin URLs no debe generar hallazgos."""
        with patch("vamp_darkweb_intel._post_form", return_value=respuesta_urlhaus_sin_resultados):
            findings = vdi._source_urlhaus("1.2.3.4", "ip")
        assert findings == []


# ── Tests para _source_threatfox ─────────────────────────────────────────────

class TestSourceThreatFox:
    """Pruebas para la fuente ThreatFox."""

    def test_botnet_cc_genera_finding_critical(self, respuesta_threatfox_positivo):
        """Un IOC de tipo botnet_cc debe generar un hallazgo CRITICAL."""
        with patch.object(vdi, "_post_json", return_value=respuesta_threatfox_positivo):
            findings = vdi._source_threatfox("185.130.5.200", "ip")

        # El primer IOC es botnet_cc → CRITICAL
        criticos = [f for f in findings if f.severity == "CRITICAL"]
        assert len(criticos) >= 1
        assert criticos[0].source == "ThreatFox"

    def test_sin_iocs_devuelve_lista_vacia(self, respuesta_threatfox_sin_resultados):
        """Una respuesta ThreatFox sin IOCs no debe generar hallazgos."""
        with patch("vamp_darkweb_intel._post_json", return_value=respuesta_threatfox_sin_resultados):
            findings = vdi._source_threatfox("empresa.com", "domain")
        assert findings == []


# ── Tests para _source_malwarebazaar ─────────────────────────────────────────

class TestSourceMalwareBazaar:
    """Pruebas para la fuente MalwareBazaar."""

    def test_hash_con_muestra_genera_critical(self, hash_objetivo, respuesta_bazaar_hash):
        """Un hash encontrado en MalwareBazaar debe generar un hallazgo CRITICAL."""
        with patch.object(vdi, "_post_form", return_value=respuesta_bazaar_hash):
            findings = vdi._source_malwarebazaar(hash_objetivo, "hash")

        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"
        assert findings[0].source == "MalwareBazaar"

    def test_tipo_no_hash_devuelve_lista_vacia(self, dominio_objetivo):
        """Para objetivos que no son hashes, MalwareBazaar devuelve lista vacía."""
        findings = vdi._source_malwarebazaar(dominio_objetivo, "domain")
        assert findings == []


# ── Tests para _source_shodan_internetdb ─────────────────────────────────────

class TestSourceShodanInternetDB:
    """Pruebas para la fuente Shodan InternetDB."""

    def test_ip_con_cves_genera_finding_high(self, respuesta_shodan_internetdb):
        """Una IP con CVEs en Shodan InternetDB debe generar un hallazgo HIGH o CRITICAL."""
        with patch.object(vdi, "_get", return_value=respuesta_shodan_internetdb):
            findings = vdi._source_shodan_internetdb("185.130.5.200", "ip")

        assert len(findings) >= 1
        sevs = {f.severity for f in findings}
        assert sevs & {"HIGH", "CRITICAL"}  # Al menos uno de los dos

    def test_tipo_no_ip_devuelve_lista_vacia(self):
        """Para objetivos que no son IPs, Shodan InternetDB devuelve lista vacía."""
        findings = vdi._source_shodan_internetdb("empresa.com", "domain")
        assert findings == []
