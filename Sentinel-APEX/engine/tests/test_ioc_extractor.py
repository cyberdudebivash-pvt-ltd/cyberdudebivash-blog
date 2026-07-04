from sentinel_engine.ioc_extractor import defang, extract_iocs, refang
from sentinel_engine.models import IOCType


def _values(iocs, ioc_type):
    return {i.value for i in iocs if i.type == ioc_type}


def test_refang_defanged_notation():
    assert refang("hxxp://evil[.]com/x") == "http://evil.com/x"
    assert refang("bad[.]domain[.]top") == "bad.domain.top"
    assert refang("user[@]evil[.]com") == "user@evil.com"


def test_defang_roundtrip():
    assert defang("http://evil.com/x", IOCType.URL) == "hxxp://evil[.]com/x"
    assert defang("1.2.3.4", IOCType.IPV4) == "1[.]2[.]3[.]4"
    assert defang("a@b.com", IOCType.EMAIL) == "a[@]b[.]com"


def test_extracts_defanged_indicators():
    text = "C2 at hxxp://update-service[.]xyz/s.ps1 and 45[.]61[.]136[.]39"
    iocs = extract_iocs(text)
    assert "http://update-service.xyz/s.ps1" in _values(iocs, IOCType.URL)
    assert "45.61.136.39" in _values(iocs, IOCType.IPV4)


def test_private_ips_excluded():
    iocs = extract_iocs("connects to 192.168.1.10 and 10.0.0.5 and 8.8.8.8")
    assert _values(iocs, IOCType.IPV4) == {"8.8.8.8"}


def test_hash_classification_no_overlap():
    sha256 = "a" * 64
    md5 = "b" * 32
    iocs = extract_iocs(f"payload {sha256} dropper {md5}")
    assert _values(iocs, IOCType.SHA256) == {sha256}
    assert _values(iocs, IOCType.MD5) == {md5}
    # the sha256 must not additionally register as md5/sha1 substrings
    assert not _values(iocs, IOCType.SHA1)


def test_allowlisted_infrastructure_not_indicators():
    text = "see https://attack.mitre.org/techniques/T1566/ and blog.cyberdudebivash.in"
    iocs = extract_iocs(text)
    assert not _values(iocs, IOCType.URL)
    assert not _values(iocs, IOCType.DOMAIN)


def test_domain_inside_url_not_double_counted():
    iocs = extract_iocs("payload at http://evil-domain.top/x.bin")
    assert "http://evil-domain.top/x.bin" in _values(iocs, IOCType.URL)
    assert not _values(iocs, IOCType.DOMAIN)


def test_cve_and_registry_extraction():
    text = r"CVE-2024-4577 persists via HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    iocs = extract_iocs(text)
    assert "CVE-2024-4577" in _values(iocs, IOCType.CVE)
    assert len(_values(iocs, IOCType.REGISTRY_KEY)) == 1


def test_filenames_not_domains():
    iocs = extract_iocs("see report.txt and setup.exe for details")
    assert not _values(iocs, IOCType.DOMAIN)
