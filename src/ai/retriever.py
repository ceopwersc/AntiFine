"""Offline, deterministic retrieval over AntiFine rules and documentation."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from src.ai.knowledge_service import KNOWLEDGE_PATH, KnowledgeService, RuleMetadata
from src.services.ai_explanation import sanitize_text

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOCS_ROOT = PROJECT_ROOT / "docs" / "ai"
INDEX_PATH = PROJECT_ROOT / ".antifine" / "knowledge_index.json"
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:/-]*", re.IGNORECASE)


@dataclass(frozen=True)
class KnowledgeChunk:
    id: str
    source: str
    title: str
    rule_id: str | None
    technology: str | None
    frameworks: tuple[str, ...]
    text: str

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["frameworks"] = list(self.frameworks)
        return value


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in _TOKEN_RE.findall(text) if len(token) > 1}


def _chunk_markdown(path: Path) -> list[KnowledgeChunk]:
    text = path.read_text(encoding="utf-8")
    sections = re.split(r"(?m)(?=^#{1,3}\s+)", text)
    chunks: list[KnowledgeChunk] = []
    for index, section in enumerate(sections):
        section = section.strip()
        if not section:
            continue
        heading = re.match(r"^#{1,3}\s+(.+)$", section)
        title = heading.group(1).strip() if heading else path.stem.replace("-", " ").title()
        chunks.append(KnowledgeChunk(
            id=f"doc:{path.stem}:{index}",
            source=str(path.relative_to(PROJECT_ROOT)).replace("\\", "/"),
            title=title,
            rule_id=None,
            technology=None,
            frameworks=(),
            text=section,
        ))
    return chunks


class Retriever:
    """Cached local index with exact-ID and lexical ranking."""

    def __init__(self, index_path: Path = INDEX_PATH) -> None:
        self.index_path = index_path
        self._chunks: tuple[KnowledgeChunk, ...] | None = None

    def build_index(self) -> list[KnowledgeChunk]:
        service = KnowledgeService()
        chunks = [
            KnowledgeChunk(
                id=f"rule:{rule.rule_id}",
                source=rule.source,
                title=rule.title,
                rule_id=rule.rule_id,
                technology=rule.technology,
                frameworks=rule.frameworks,
                text=rule.as_prompt_context(),
            )
            for rule in service.rules
        ]
        chunks.extend(chunk for path in sorted(DOCS_ROOT.glob("*.md")) for chunk in _chunk_markdown(path))
        self._chunks = tuple(chunks)
        return list(self._chunks)

    def rebuild_index(self) -> list[KnowledgeChunk]:
        chunks = self.build_index()
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "chunks": [chunk.as_dict() for chunk in chunks]}
        self.index_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return chunks

    def _load_index(self) -> tuple[KnowledgeChunk, ...]:
        if self._chunks is not None:
            return self._chunks
        if not self.index_path.is_file():
            self._chunks = tuple(self.build_index())
            return self._chunks
        try:
            payload = json.loads(self.index_path.read_text(encoding="utf-8"))
            raw_chunks = payload["chunks"]
            self._chunks = tuple(
                KnowledgeChunk(
                    id=str(item["id"]),
                    source=str(item["source"]),
                    title=str(item["title"]),
                    rule_id=item.get("rule_id"),
                    technology=item.get("technology"),
                    frameworks=tuple(item.get("frameworks", [])),
                    text=str(item["text"]),
                )
                for item in raw_chunks
            )
        except (OSError, KeyError, TypeError, ValueError):
            self._chunks = tuple(self.build_index())
        return self._chunks

    def retrieve(self, query: str, top_k: int = 5) -> list[KnowledgeChunk]:
        if top_k <= 0 or not query.strip():
            return []
        query = sanitize_text(query, limit=4000)
        query_terms = _tokens(query)
        chunks = self._load_index()
        scored: list[tuple[int, int, KnowledgeChunk]] = []
        for position, chunk in enumerate(chunks):
            searchable = " ".join((
                chunk.id,
                chunk.title,
                chunk.source,
                chunk.technology or "",
                " ".join(chunk.frameworks),
                chunk.text,
            )).lower()
            score = len(query_terms & _tokens(searchable))
            if chunk.rule_id and chunk.rule_id.lower() in query.lower():
                score += 100
            if chunk.technology and chunk.technology.lower() in query.lower():
                score += 10
            if score:
                scored.append((score, -position, chunk))
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [chunk for _, _, chunk in scored[:top_k]]


_RETRIEVER = Retriever()


def retrieve(query: str, top_k: int = 5) -> list[KnowledgeChunk]:
    return _RETRIEVER.retrieve(query, top_k)


def build_index() -> list[KnowledgeChunk]:
    return _RETRIEVER.build_index()


def rebuild_index() -> list[KnowledgeChunk]:
    return _RETRIEVER.rebuild_index()
