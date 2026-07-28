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


def test_citation_urls_after_sources_marker_excluded():
    text = (
        "CVE-2026-99999 is actively exploited using a dropper hosted at "
        "https://evil-payload-drop.xyz/stage2.bin.\n\n"
        "Sources:\n"
        "- https://thehackernews.com/2026/07/example-vuln-exploited.html\n"
        "- https://www.helpnetsecurity.com/2026/07/22/example-vuln/\n"
        "- https://www.securityweek.com/example-vuln-exploited-wave/\n"
    )
    iocs = extract_iocs(text)
    urls = _values(iocs, IOCType.URL)
    assert urls == {"https://evil-payload-drop.xyz/stage2.bin"}
    assert "CVE-2026-99999" in _values(iocs, IOCType.CVE)


def test_citation_urls_after_references_heading_excluded():
    text = (
        "Payload retrieved from https://bad-domain.top/x.bin during initial access.\n\n"
        "## References\n"
        "- https://www.bleepingcomputer.com/news/security/example/\n"
    )
    iocs = extract_iocs(text)
    urls = _values(iocs, IOCType.URL)
    assert urls == {"https://bad-domain.top/x.bin"}


def test_malicious_url_before_marker_still_extracted():
    text = (
        "The malware retrieves its second stage from https://evil-payload-drop.xyz/s2.bin.\n\n"
        "References:\n"
        "- https://thehackernews.com/2026/07/example.html\n"
    )
    iocs = extract_iocs(text)
    assert _values(iocs, IOCType.URL) == {"https://evil-payload-drop.xyz/s2.bin"}


def test_no_citation_marker_all_urls_still_extracted():
    text = (
        "Malware stages from https://evil-payload-drop.xyz/stage2.bin and beacons to "
        "https://185.220.101.45/gate.php every 60 seconds."
    )
    iocs = extract_iocs(text)
    urls = _values(iocs, IOCType.URL)
    assert "https://evil-payload-drop.xyz/stage2.bin" in urls
    assert "https://185.220.101.45/gate.php" in urls


def test_bare_word_sources_in_prose_is_not_treated_as_marker():
    text = (
        "Related sources and context indicate this campaign reuses infrastructure "
        "from https://evil-payload-drop.xyz/stage2.bin.\n"
    )
    iocs = extract_iocs(text)
    assert "https://evil-payload-drop.xyz/stage2.bin" in _values(iocs, IOCType.URL)


def test_tech_name_asp_net_not_classified_as_domain():
    # platform/open-issues.md Issue 9: "ASP.NET" (the credential-theft
    # mechanism named throughout SA-2026-0001) is shaped like a domain
    # (word.tld, and "net" is a real, accepted TLD) and was misclassified
    # as one before TECH_NAME_ALLOWLIST existed.
    text = "Credentials were harvested from the ASP.NET machine key configuration."
    iocs = extract_iocs(text)
    assert "asp.net" not in _values(iocs, IOCType.DOMAIN)


def test_tech_name_allowlist_does_not_suppress_a_real_dot_net_domain():
    # TECH_NAME_ALLOWLIST must be narrowly scoped to the exact confirmed
    # string, not to the .net TLD generally -- a genuinely malicious .net
    # domain must still extract correctly.
    text = "The payload beacons to evil-c2-panel.net every 60 seconds."
    iocs = extract_iocs(text)
    assert "evil-c2-panel.net" in _values(iocs, IOCType.DOMAIN)
