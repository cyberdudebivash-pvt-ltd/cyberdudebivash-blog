"""Intelligence knowledge graph: a persistent, JSON-backed store of entities
and relationships accumulated across reports.

Each ingested report enriches the graph, so future reports gain context:
"this CVE was previously tied to that actor", "this domain appeared in an
earlier campaign". Deliberately simple (no external DB) so it can run inside
CI and be versioned alongside the repository.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import NormalizedDoc


@dataclass
class KnowledgeGraph:
    # entity key "type:name" -> {"type", "name", "reports": [report_id...]}
    entities: dict[str, dict] = field(default_factory=dict)
    # relation triple list: {"src", "rel", "dst", "report"}
    relations: list[dict] = field(default_factory=list)

    # --- construction -------------------------------------------------------

    @staticmethod
    def _key(etype: str, name: str) -> str:
        return f"{etype}:{name.lower()}"

    def upsert_entity(self, etype: str, name: str, report_id: str = "") -> str:
        key = self._key(etype, name)
        node = self.entities.setdefault(
            key, {"type": etype, "name": name, "reports": []}
        )
        if report_id and report_id not in node["reports"]:
            node["reports"].append(report_id)
        return key

    def relate(self, src_key: str, rel: str, dst_key: str, report_id: str = "") -> None:
        triple = {"src": src_key, "rel": rel, "dst": dst_key, "report": report_id}
        if triple not in self.relations:
            self.relations.append(triple)

    def ingest(self, doc: NormalizedDoc, report_id: str) -> None:
        """Add a normalized document's observations to the graph."""
        report_key = self.upsert_entity("report", report_id, report_id)

        for entity in doc.entities:
            key = self.upsert_entity(entity.type, entity.name, report_id)
            self.relate(report_key, "mentions", key, report_id)

        for cve in doc.cves:
            key = self.upsert_entity("cve", cve, report_id)
            self.relate(report_key, "references", key, report_id)

        for technique in doc.techniques:
            key = self.upsert_entity("technique", technique.technique_id, report_id)
            self.relate(report_key, "maps_to", key, report_id)

        for ioc in doc.iocs:
            if ioc.type.value == "cve":
                continue
            key = self.upsert_entity(f"ioc_{ioc.type.value}", ioc.value, report_id)
            self.relate(report_key, "observed", key, report_id)

        # co-occurrence edges: actor <-> malware/cve/technique in same report
        actors = [e for e in doc.entities if e.type == "threat_actor"]
        for actor in actors:
            a_key = self._key("threat_actor", actor.name)
            for entity in doc.entities:
                if entity.type in ("malware", "tool"):
                    self.relate(
                        a_key, "associated_with",
                        self._key(entity.type, entity.name), report_id,
                    )
            for cve in doc.cves:
                self.relate(a_key, "linked_to", self._key("cve", cve), report_id)

    # --- queries ------------------------------------------------------------

    def neighbors(self, key: str) -> list[dict]:
        return [
            r for r in self.relations if key in (r["src"], r["dst"])
        ]

    def prior_context(self, doc: NormalizedDoc) -> list[str]:
        """Human-readable notes on what the graph already knows about the
        entities in a new document — feeds the analyst layer."""
        notes: list[str] = []
        candidates = [(e.type, e.name) for e in doc.entities]
        candidates += [("cve", c) for c in doc.cves]
        for etype, name in candidates:
            key = self._key(etype, name)
            node = self.entities.get(key)
            if node and node["reports"]:
                notes.append(
                    f"{name} ({etype}) previously appeared in "
                    f"{len(node['reports'])} report(s): "
                    + ", ".join(node["reports"][-5:])
                )
        return notes

    def stats(self) -> dict:
        by_type: dict[str, int] = {}
        for node in self.entities.values():
            by_type[node["type"]] = by_type.get(node["type"], 0) + 1
        return {
            "entities": len(self.entities),
            "relations": len(self.relations),
            "by_type": dict(sorted(by_type.items())),
        }

    # --- persistence --------------------------------------------------------

    def save(self, path: str | Path) -> None:
        payload = {"entities": self.entities, "relations": self.relations}
        Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> "KnowledgeGraph":
        p = Path(path)
        if not p.exists():
            return cls()
        payload = json.loads(p.read_text())
        return cls(
            entities=payload.get("entities", {}),
            relations=payload.get("relations", []),
        )
