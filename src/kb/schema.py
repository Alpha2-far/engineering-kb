"""Contrat de donnees de la Knowledge Base.

Loi n(deg)1 appliquee a la KB elle-meme : faits != interpretations.

Une regle est une *interpretation* (produite par un extracteur LLM a partir d'un
document). Sa citation est un *fait* (une chaine de caracteres presente dans un
document archive, verifiable sans LLM). Le schema force les deux a coexister :
aucune regle ne peut exister sans au moins une `Evidence` verifiable dans
`kb/raw/`. C'est ce qui empeche la base de devenir une machine a blanchir des
hallucinations : une reference inventee est mecaniquement rejetee au moment de la
validation, pas detectee par relecture humaine.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# --------------------------------------------------------------------------- #
# Vocabulaires controles
# --------------------------------------------------------------------------- #


class Category(str, Enum):
    """Les 19 domaines de la mission. Un vocabulaire ferme : une categorie
    inventee casse le build, ce qui evite la derive de taxonomie a 200 regles."""

    APP_SECURITY = "app-security"
    ARCHITECTURE = "architecture"
    CODE_QUALITY = "code-quality"
    PERFORMANCE = "performance"
    DATABASE = "database"
    DEVOPS = "devops"
    CLOUD = "cloud"
    CRYPTOGRAPHY = "cryptography"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    API = "api"
    FRONTEND = "frontend"
    BACKEND = "backend"
    MOBILE = "mobile"
    AI_ML = "ai-ml"
    DATA_PROTECTION = "data-protection"
    COMPLIANCE = "compliance"
    PRODUCTION = "production-readiness"


class Severity(str, Enum):
    """Severite = consequence si la regle est violee en production."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Confiance dans la *fidelite de l'extraction* par rapport a la source.

    HIGH   : la source enonce l'exigence explicitement (« MUST », « never »).
    MEDIUM : la source la recommande sans l'imposer, ou l'extracteur a reformule.
    LOW    : deduite du contexte. A relire par un humain avant application auto.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DetectionKind(str, Enum):
    """Comment un agent peut *mecaniquement* accrocher la regle a du code.

    Une regle sans condition de detection concrete produit des constats vagues
    (« verifier que l'auth est correcte »), c'est-a-dire du bruit. MANUAL reste
    permis mais doit rester rare et signale.
    """

    GREP = "grep"  # regex sur le contenu des fichiers
    ABSENT = "absent"  # un motif qui DOIT etre present et manque
    AST = "ast"  # structure du code (appel, decorateur, argument)
    CONFIG = "config"  # cle/valeur dans un fichier de configuration
    DEPENDENCY = "dependency"  # presence/version d'une dependance
    MANUAL = "manual"  # necessite un jugement humain


class Autofix(str, Enum):
    """Une correction peut-elle etre appliquee automatiquement sans risque ?

    Gouverne l'autorisation d'ecriture des agents correcteurs. `NEVER` protege
    les regles dont le correctif depend d'une intention metier.
    """

    SAFE = "safe"  # remplacement mecanique, sans perte de comportement
    REVIEW = "review"  # correctif propose, validation humaine requise
    NEVER = "never"  # depend d'une decision metier / architecture


# --------------------------------------------------------------------------- #
# Composants
# --------------------------------------------------------------------------- #

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
RULE_ID_RE = re.compile(
    r"^[a-z0-9-]+/[a-z0-9-]+/[a-z0-9]+(?:-[a-z0-9]+)*$"
)  # categorie/sous-categorie/slug


class Evidence(BaseModel):
    """Le *fait* qui fonde la regle : une citation localisable et verifiable.

    `quote` doit apparaitre dans le document archive `doc_path` (verification
    deterministe par `kb.ground`). C'est la seule partie de la regle qui n'est
    pas une interpretation, et donc la seule qu'on puisse opposer a quelqu'un.
    """

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(description="Identifiant de la source dans le registre")
    doc_path: str = Field(description="Chemin du document, relatif a kb/raw/")
    doc_sha256: str = Field(description="Empreinte du document au moment de l'extraction")
    quote: str = Field(
        min_length=40,
        description="Extrait litteral de la source. >=40 car en dessous une citation "
        "n'est pas discriminante et matcherait n'importe quoi.",
    )
    url: str | None = Field(default=None, description="URL publique citable dans un rapport")
    anchor: str | None = Field(default=None, description="Section / ancre dans le document")

    @field_validator("doc_sha256")
    @classmethod
    def _sha_format(cls, v: str) -> str:
        if not SHA256_RE.match(v):
            raise ValueError("doc_sha256 doit etre un sha256 hexadecimal minuscule (64 car.)")
        return v

    @field_validator("source_id")
    @classmethod
    def _source_slug(cls, v: str) -> str:
        if not SLUG_RE.match(v):
            raise ValueError(f"source_id doit etre un slug kebab-case : {v!r}")
        return v


class Detection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: DetectionKind
    pattern: str = Field(
        min_length=3,
        description="Regex (GREP/ABSENT), expression de config (CONFIG), "
        "specificateur de dependance (DEPENDENCY), ou consigne precise (MANUAL)",
    )
    applies_to: list[str] = Field(
        default_factory=list,
        description="Globs de fichiers concernes, ex. ['**/*.py']. Vide = tout fichier.",
    )
    note: str | None = None

    @model_validator(mode="after")
    def _regex_must_compile(self) -> Detection:
        # Une regex invalide casserait l'agent au moment du scan, pas ici.
        # On paie le cout de la verification a la construction de la KB.
        if self.kind in (DetectionKind.GREP, DetectionKind.ABSENT):
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"pattern regex invalide ({self.kind.value}) : {exc}") from exc
        return self


class CodeExample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lang: str = Field(description="Langage / format, ex. python, ts, sql, yaml, nginx")
    code: str = Field(min_length=10)
    explanation: str | None = None


class RuleContext(BaseModel):
    """Quand la regle s'applique. C'est ce qui rend le routage possible :
    un agent qui audite un site statique vanilla ne doit pas charger les regles
    pgvector. Sans ce filtre, la KB noie l'agent au lieu de l'outiller."""

    model_config = ConfigDict(extra="forbid")

    languages: list[str] = Field(default_factory=list, description="python, typescript, sql…")
    frameworks: list[str] = Field(default_factory=list, description="fastapi, react, next…")
    platforms: list[str] = Field(default_factory=list, description="supabase, railway, vercel…")
    project_types: list[str] = Field(
        default_factory=list,
        description="static-site, saas, ai-rag, api, pipeline, cli, mobile. Vide = universel.",
    )
    applies_when: str | None = Field(
        default=None, description="Condition en clair, ex. « uniquement si l'app expose une API publique »"
    )


# --------------------------------------------------------------------------- #
# La regle
# --------------------------------------------------------------------------- #


class Rule(BaseModel):
    """Une regle d'ingenierie exploitable par un agent.

    L'`id` est un chemin `categorie/sous-categorie/slug` plutot qu'un compteur :
    des extracteurs qui tournent en parallele ne peuvent pas se coordonner sur un
    numero, alors qu'un slug descriptif est unique par construction et reste
    stable si on re-extrait la source.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str = Field(min_length=10, max_length=120)
    category: Category
    subcategory: str = Field(description="Slug kebab-case libre sous la categorie")
    severity: Severity
    confidence: Confidence

    description: str = Field(
        min_length=40, description="Ce que la regle exige, en une a trois phrases"
    )
    rationale: str = Field(
        min_length=40,
        description="Pourquoi techniquement. Ce qui casse si on l'ignore — pas une "
        "paraphrase de la description.",
    )
    remediation: str = Field(min_length=20, description="Comment corriger, concretement")

    context: RuleContext = Field(default_factory=RuleContext)
    detection: list[Detection] = Field(min_length=1)
    autofix: Autofix = Autofix.REVIEW

    vulnerable_example: CodeExample | None = None
    fixed_example: CodeExample | None = None

    do_pattern: str | None = Field(
        default=None,
        description="Snippet de code sécurisé recommandé (si omis, dérivé de fixed_example)",
    )
    dont_pattern: str | None = Field(
        default=None,
        description="Snippet de code vulnérable fréquent (si omis, dérivé de vulnerable_example)",
    )
    frameworks: list[str] = Field(
        default_factory=list,
        description="Frameworks et libs cibles (ex. fastapi, supabase, nextjs, docker, jwt, pgvector)",
    )

    evidence: list[Evidence] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)

    cwe: list[str] = Field(default_factory=list, description="ex. ['CWE-89']")
    owasp: list[str] = Field(default_factory=list, description="ex. ['A01:2025', 'LLM01:2025']")

    extracted_at: str = Field(description="Date ISO de l'extraction")
    extractor: str = Field(description="Qui a extrait (modele/agent), pour la tracabilite")

    @property
    def effective_do_pattern(self) -> str | None:
        """Extrait de code sécurisé de référence."""
        if self.do_pattern:
            return self.do_pattern
        return self.fixed_example.code if self.fixed_example else None

    @property
    def effective_dont_pattern(self) -> str | None:
        """Extrait de code vulnérable représentatif du piège LLM."""
        if self.dont_pattern:
            return self.dont_pattern
        return self.vulnerable_example.code if self.vulnerable_example else None

    @property
    def all_frameworks(self) -> list[str]:
        """Agrège les frameworks déclarés au niveau racine et dans context."""
        fw = set(self.frameworks)
        if self.context:
            fw.update(self.context.frameworks)
        return sorted(fw)

    def to_agent_card(self) -> dict:
        """Vue condensée taillée pour être injectée dans la fenêtre de contexte d'un agent."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "frameworks": self.all_frameworks,
            "rationale": self.rationale.strip(),
            "remediation": self.remediation.strip(),
            "do_pattern": self.effective_do_pattern,
            "dont_pattern": self.effective_dont_pattern,
            "official_citation": self.evidence[0].quote if self.evidence else None,
            "source_id": self.evidence[0].source_id if self.evidence else None,
        }


    @field_validator("id")
    @classmethod
    def _id_format(cls, v: str) -> str:
        if not RULE_ID_RE.match(v):
            raise ValueError(
                f"id doit etre 'categorie/sous-categorie/slug' en kebab-case : {v!r}"
            )
        return v

    @field_validator("subcategory")
    @classmethod
    def _subcat_slug(cls, v: str) -> str:
        if not SLUG_RE.match(v):
            raise ValueError(f"subcategory doit etre un slug kebab-case : {v!r}")
        return v

    @model_validator(mode="after")
    def _id_matches_taxonomy(self) -> Rule:
        cat, sub, _ = self.id.split("/")
        if cat != self.category.value:
            raise ValueError(f"id commence par {cat!r} mais category={self.category.value!r}")
        if sub != self.subcategory:
            raise ValueError(f"id contient {sub!r} mais subcategory={self.subcategory!r}")
        return self

    @model_validator(mode="after")
    def _severe_rules_need_examples(self) -> Rule:
        # Une regle critique sans exemple avant/apres n'est pas actionnable :
        # l'agent sait qu'il y a un probleme mais pas a quoi ressemble le correctif.
        if self.severity in (Severity.CRITICAL, Severity.HIGH):
            missing = [
                name
                for name, val in (
                    ("vulnerable_example", self.vulnerable_example),
                    ("fixed_example", self.fixed_example),
                )
                if val is None
            ]
            if missing:
                raise ValueError(
                    f"severite {self.severity.value} exige {' et '.join(missing)}"
                )
        return self

    @model_validator(mode="after")
    def _autofix_safe_needs_fix_example(self) -> Rule:
        if self.autofix is Autofix.SAFE and self.fixed_example is None:
            raise ValueError("autofix=safe exige un fixed_example : on n'applique pas a l'aveugle")
        return self

    @model_validator(mode="after")
    def _detection_not_only_manual(self) -> Rule:
        if all(d.kind is DetectionKind.MANUAL for d in self.detection) and self.severity in (
            Severity.CRITICAL,
            Severity.HIGH,
        ):
            raise ValueError(
                "une regle critical/high entierement MANUAL ne sera jamais declenchee "
                "par un agent : ajouter au moins une detection mecanique"
            )
        return self


class RulePack(BaseModel):
    """Le fichier YAML livre par un extracteur : les regles tirees d'une source."""

    model_config = ConfigDict(extra="forbid")

    source_id: str
    rules: list[Rule]


class SecurityTopic(BaseModel):
    """Index de résolution sémantique associant des intentions d'agents à des règles."""

    model_config = ConfigDict(extra="forbid")

    slug: str = Field(description="Identifiant unique du topic, ex. fastapi-jwt")
    title: str = Field(description="Nom lisible du topic")
    keywords: list[str] = Field(default_factory=list, description="Mots-clés naturels")
    frameworks: list[str] = Field(default_factory=list, description="Frameworks concernés")
    rule_ids: list[str] = Field(default_factory=list, description="IDs de règles associées")
    description: str = Field(default="", description="Courte explication du risque")

