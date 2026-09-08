"""Chargement et validation du registre de sources."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

KB_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = KB_ROOT / "sources" / "registry.yaml"
RAW_DIR = KB_ROOT / "raw"
RULES_DIR = KB_ROOT / "rules"
PACKS_DIR = KB_ROOT / "packs"
MANIFEST_PATH = RAW_DIR / "manifest.jsonl"


class Method(str, Enum):
    GIT = "git"
    HTTP = "http"
    FEED = "feed"
    FIRECRAWL = "firecrawl"
    MANUAL = "manual"


class Source(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    tier: int = Field(ge=1, le=3)
    method: Method
    license: str
    redistribute: bool
    categories: list[str] = Field(default_factory=list)
    note: str | None = None

    # git
    repo: str | None = None
    ref: str | None = None
    paths: list[str] = Field(default_factory=list)

    # http / feed
    urls: list[str] = Field(default_factory=list)
    format: str | None = None

    # firecrawl
    discover: str | None = None

    @model_validator(mode="after")
    def _method_requirements(self) -> Source:
        if self.method is Method.GIT and not self.repo:
            raise ValueError(f"[{self.id}] method=git exige `repo`")
        if self.method in (Method.HTTP, Method.FEED) and not self.urls:
            raise ValueError(f"[{self.id}] method={self.method.value} exige `urls`")
        if self.method is Method.FIRECRAWL and not (self.discover or self.urls):
            # Firecrawl est la seule ressource payante du pipeline. Sans `urls`
            # explicites ni requete `discover`, on ne saurait pas quoi scraper —
            # et un crawl a l'aveugle viderait le budget du mois.
            raise ValueError(f"[{self.id}] method=firecrawl exige `urls` ou `discover`")
        return self


class RegistryMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    updated: str
    credit_budget_note: str | None = None


class Registry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: RegistryMeta
    sources: list[Source]

    @model_validator(mode="after")
    def _unique_ids(self) -> Registry:
        seen: set[str] = set()
        for s in self.sources:
            if s.id in seen:
                raise ValueError(f"source_id duplique : {s.id}")
            seen.add(s.id)
        return self

    def by_id(self, source_id: str) -> Source:
        for s in self.sources:
            if s.id == source_id:
                return s
        raise KeyError(f"source inconnue : {source_id}")

    def select(
        self, *, tier: int | None = None, method: Method | None = None, ids: list[str] | None = None
    ) -> list[Source]:
        out = self.sources
        if ids:
            wanted = set(ids)
            out = [s for s in out if s.id in wanted]
        if tier is not None:
            out = [s for s in out if s.tier <= tier]
        if method is not None:
            out = [s for s in out if s.method is method]
        return out


def load_registry(path: Path | None = None) -> Registry:
    p = path or REGISTRY_PATH
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    return Registry.model_validate(data)
