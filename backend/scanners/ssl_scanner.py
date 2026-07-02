from __future__ import annotations

import asyncio
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# TLS ports scanned during SSL analysis
SSL_PORTS = frozenset({443, 8443, 4443, 9443, 8444, 10443, 636, 993, 995, 465, 587})

_WEAK_TLS    = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})
_WEAK_CIPHER = frozenset({"RC4", "DES", "3DES", "NULL", "EXPORT", "RC2", "ANON"})

try:
    from cryptography import x509 as _x509
    from cryptography.hazmat.backends import default_backend as _default_backend
    from cryptography.x509.oid import NameOID as _NameOID
    _CRYPTO = True
except ImportError:
    _CRYPTO = False
    logger.warning("[SSL] 'cryptography' package not available — certificate details will be limited")


def is_ssl_port(port: int, service: str) -> bool:
    svc = (service or "").lower()
    return port in SSL_PORTS or "https" in svc or "ssl/" in svc or "tls" in svc


async def analyze_ssl(host: str, port: int, timeout: float = 8.0) -> Optional[Dict[str, Any]]:
    """
    Connect to host:port over TLS, collect certificate + cipher info.
    Returns an ssl_info dict or None on failure.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=timeout,
        )

        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            writer.close()
            return None

        der_cert    = ssl_obj.getpeercert(binary_form=True)
        tls_version = ssl_obj.version() or "Unknown"
        cipher_info = ssl_obj.cipher()  # (name, protocol, bits)

        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass

        cipher_name = cipher_info[0] if cipher_info else "Unknown"
        cipher_bits = cipher_info[2] if cipher_info else 0

        result: Dict[str, Any] = {
            "port":          port,
            "tlsVersion":    tls_version,
            "cipherSuite":   cipher_name,
            "cipherBits":    cipher_bits or 0,
            "isWeakTls":     tls_version in _WEAK_TLS,
            "isWeakCipher":  any(k in cipher_name.upper() for k in _WEAK_CIPHER),
            "subject":       "Unknown",
            "issuer":        "Unknown",
            "notBefore":     None,
            "notAfter":      None,
            "daysUntilExpiry": None,
            "isExpired":     False,
            "expiringSoon":  False,
            "isSelfSigned":  False,
            "sans":          [],
        }

        if der_cert and _CRYPTO:
            _enrich_from_cert(result, der_cert)

        return result

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception as exc:
        logger.debug(f"[SSL] {host}:{port} error: {exc}")
        return None


def _enrich_from_cert(result: Dict[str, Any], der_cert: bytes) -> None:
    try:
        cert = _x509.load_der_x509_certificate(der_cert, _default_backend())
        now  = datetime.now(timezone.utc)

        try:
            not_after  = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
        except AttributeError:
            # cryptography < 42 returns naive datetimes
            not_after  = cert.not_valid_after.replace(tzinfo=timezone.utc)
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

        days = (not_after - now).days

        def _cn(name):
            try:
                return name.get_attributes_for_oid(_NameOID.COMMON_NAME)[0].value
            except Exception:
                return str(name)

        subject_cn = _cn(cert.subject)
        issuer_cn  = _cn(cert.issuer)

        try:
            san_ext = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
            sans    = [str(n.value) for n in san_ext.value][:10]
        except _x509.ExtensionNotFound:
            sans = [subject_cn] if subject_cn and subject_cn != "Unknown" else []

        result.update({
            "subject":         subject_cn,
            "issuer":          issuer_cn,
            "notBefore":       not_before.isoformat(),
            "notAfter":        not_after.isoformat(),
            "daysUntilExpiry": days,
            "isExpired":       now > not_after,
            "expiringSoon":    0 < days <= 30,
            "isSelfSigned":    cert.issuer == cert.subject,
            "sans":            sans,
        })
    except Exception as exc:
        logger.debug(f"[SSL] cert parse error: {exc}")


def generate_ssl_findings(
    scan_id: str,
    host: dict,
    ssl_info: Dict[str, Any],
    now_iso: str,
) -> List[dict]:
    """Return a list of security findings derived from ssl_info for a single host:port."""
    findings = []
    ip       = host["ip"]
    host_id  = host["hostId"]
    port     = ssl_info["port"]

    def _f(title: str, severity: str, description: str, recommendation: str, evidence: str) -> dict:
        return {
            "findingId":      f"ssl_{uuid.uuid4().hex[:12]}",
            "scanId":         scan_id,
            "hostId":         host_id,
            "ip":             ip,
            "source":         "ssl-analysis",
            "severity":       severity,
            "title":          title,
            "template":       f"ssl-{severity}-{port}",
            "host":           ip,
            "matched_at":     f"https://{ip}:{port}",
            "description":    description,
            "recommendation": recommendation,
            "port":           port,
            "protocol":       "tcp",
            "evidence":       evidence,
            "createdAt":      now_iso,
        }

    if ssl_info.get("isExpired"):
        days = abs(ssl_info.get("daysUntilExpiry") or 0)
        findings.append(_f(
            title="Expired SSL/TLS Certificate",
            severity="critical",
            description=(
                f"The certificate on {ip}:{port} expired {days} day(s) ago. "
                "Clients receive certificate errors and the connection can no longer be trusted."
            ),
            recommendation=(
                "Renew the certificate immediately via your CA or Let's Encrypt. "
                "Automate renewal with certbot and set monitoring alerts for expiry within 30 days."
            ),
            evidence=f"Expired {days}d ago. Subject: {ssl_info.get('subject', 'Unknown')}. "
                     f"Not After: {ssl_info.get('notAfter', 'N/A')}",
        ))
    elif ssl_info.get("expiringSoon"):
        days = ssl_info.get("daysUntilExpiry", 0)
        findings.append(_f(
            title=f"SSL/TLS Certificate Expiring Soon ({days}d)",
            severity="medium",
            description=(
                f"The certificate on {ip}:{port} expires in {days} day(s). "
                "Once expired, clients will refuse connections."
            ),
            recommendation=(
                "Renew before expiry. Configure automated renewal (certbot --renew) "
                "and set monitoring alerts for certificates expiring within 30 days."
            ),
            evidence=f"Expires in {days}d. Not After: {ssl_info.get('notAfter', 'N/A')}",
        ))

    if ssl_info.get("isSelfSigned"):
        findings.append(_f(
            title="Self-Signed SSL/TLS Certificate",
            severity="medium",
            description=(
                f"The certificate on {ip}:{port} is self-signed. "
                "Self-signed certs are not trusted by clients by default and are "
                "vulnerable to MITM attacks as authenticity cannot be verified."
            ),
            recommendation=(
                "Replace with a certificate from a trusted CA. "
                "Use Let's Encrypt for public-facing services (free) or an internal CA for internal services."
            ),
            evidence=f"Subject == Issuer: {ssl_info.get('subject', 'Unknown')}",
        ))

    if ssl_info.get("isWeakTls"):
        ver = ssl_info.get("tlsVersion", "Unknown")
        findings.append(_f(
            title=f"Weak TLS Protocol Version ({ver})",
            severity="high",
            description=(
                f"The server at {ip}:{port} uses {ver}, which is deprecated. "
                "Known attacks: POODLE (SSLv3), BEAST (TLS 1.0), SLOTH (TLS 1.1)."
            ),
            recommendation=(
                "Disable TLS 1.0/1.1 and configure a minimum of TLS 1.2 with TLS 1.3 preferred. "
                "Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 | "
                "Nginx: ssl_protocols TLSv1.2 TLSv1.3"
            ),
            evidence=f"Negotiated: {ver} with {ssl_info.get('cipherSuite', 'Unknown')}",
        ))

    if ssl_info.get("isWeakCipher"):
        cipher = ssl_info.get("cipherSuite", "Unknown")
        findings.append(_f(
            title=f"Weak TLS Cipher Suite ({cipher})",
            severity="high",
            description=(
                f"The server at {ip}:{port} negotiated a weak cipher ({cipher}). "
                "Weak ciphers can be exploited to decrypt traffic or forge data."
            ),
            recommendation=(
                "Configure only strong cipher suites: ECDHE+AESGCM, ECDHE+CHACHA20. "
                "Use Mozilla SSL Config Generator for recommended settings: ssl-config.mozilla.org"
            ),
            evidence=f"Cipher: {cipher} ({ssl_info.get('cipherBits', 0)} bits)",
        ))

    return findings
