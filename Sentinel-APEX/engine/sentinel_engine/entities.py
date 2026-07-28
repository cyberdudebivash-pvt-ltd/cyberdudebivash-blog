"""Named-entity extraction against a curated threat lexicon.

Only entities present in the lexicon are extracted — no guessing. The lexicon
is intentionally small and high-precision; extend it as coverage grows.
"""

from __future__ import annotations

import re

from .models import Entity

# name (canonical) -> (type, aliases)
LEXICON: dict[str, tuple[str, tuple[str, ...]]] = {
    # threat actors / intrusion sets
    "APT28": ("threat_actor", ("Fancy Bear", "Forest Blizzard", "Sofacy")),
    "APT29": ("threat_actor", ("Cozy Bear", "Midnight Blizzard", "Nobelium")),
    "APT41": ("threat_actor", ("Winnti", "Brass Typhoon")),
    "Lazarus Group": ("threat_actor", ("Lazarus", "Hidden Cobra", "Diamond Sleet")),
    "Kimsuky": ("threat_actor", ("Emerald Sleet", "Velvet Chollima")),
    "Sandworm": ("threat_actor", ("Seashell Blizzard", "Voodoo Bear")),
    "Volt Typhoon": ("threat_actor", ()),
    "Salt Typhoon": ("threat_actor", ()),
    "Scattered Spider": ("threat_actor", ("Octo Tempest", "UNC3944")),
    "FIN7": ("threat_actor", ("Carbanak Group",)),
    "TA505": ("threat_actor", ()),
    "MuddyWater": ("threat_actor", ("Mango Sandstorm",)),
    "Turla": ("threat_actor", ("Secret Blizzard", "Venomous Bear")),
    "NSO Group": ("threat_actor", ("NSO",)),
    # malware / tooling
    "Pegasus": ("malware", ()),
    "LockBit": ("malware", ("LockBit 3.0", "LockBit Black")),
    "ALPHV": ("malware", ("BlackCat",)),
    "Cl0p": ("malware", ("Clop",)),
    "Akira": ("malware", ()),
    "RansomHub": ("malware", ()),
    "Qilin": ("malware", ()),
    "BianLian": ("malware", ()),
    "Jasmin": ("malware", ()),
    "Emotet": ("malware", ()),
    "Qakbot": ("malware", ("QBot",)),
    "Cobalt Strike": ("tool", ()),
    "Mimikatz": ("tool", ()),
    "Sliver": ("tool", ()),
    "AgentTesla": ("malware", ("Agent Tesla",)),
    "LummaC2": ("malware", ("Lumma Stealer", "Lumma")),
    "RedLine": ("malware", ("RedLine Stealer",)),
    "XWorm": ("malware", ()),
    "AsyncRAT": ("malware", ()),
    "IcedID": ("malware", ()),
    "TrickBot": ("malware", ()),
    # vendors / products commonly targeted
    "Microsoft": ("vendor", ()),
    "Cisco": ("vendor", ()),
    "Fortinet": ("vendor", ("FortiGate", "FortiOS")),
    "Ivanti": ("vendor", ()),
    "Palo Alto Networks": ("vendor", ("PAN-OS",)),
    "Citrix": ("vendor", ("NetScaler",)),
    "VMware": ("vendor", ("ESXi", "vCenter")),
    "SonicWall": ("vendor", ()),
    "MOVEit": ("product", ("MOVEit Transfer",)),
    "ScreenConnect": ("product", ("ConnectWise ScreenConnect",)),
    "JetBrains": ("vendor", ()),
    "TeamCity": ("product", ("TeamCity On-Premises",)),
}


def _patterns() -> list[tuple[re.Pattern, str, str]]:
    pats = []
    for canonical, (etype, aliases) in LEXICON.items():
        for name in (canonical, *aliases):
            pats.append(
                (re.compile(r"\b%s\b" % re.escape(name), re.IGNORECASE), canonical, etype)
            )
    return pats


_PATTERNS = _patterns()


def extract_entities(text: str) -> list[Entity]:
    found: dict[str, Entity] = {}
    for pattern, canonical, etype in _PATTERNS:
        if canonical in found:
            continue
        m = pattern.search(text)
        if not m:
            continue
        start = max(0, m.start() - 50)
        context = " ".join(text[start : m.end() + 50].split())
        found[canonical] = Entity(name=canonical, type=etype, context=context)
    return sorted(found.values(), key=lambda e: (e.type, e.name))
