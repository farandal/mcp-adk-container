# Technical Documentation — phishing-detector MCP Server

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Project Structure](#3-project-structure)
4. [Core Modules](#4-core-modules)
   - [4.1 Shared Types (`src/core/types.py`)](#41-shared-types)
   - [4.2 Anthropic Client Factory (`src/core/claude.py`)](#42-anthropic-client-factory)
5. [Phishing Domain Logic](#5-phishing-domain-logic)
   - [5.1 Static Pattern Detection (`domain/patterns.py`)](#51-static-pattern-detection)
   - [5.2 WHOIS Lookup (`domain/whois.py`)](#52-whois-lookup)
   - [5.3 CMF Verification (`domain/cmf.py`)](#53-cmf-verification)
   - [5.4 Orchestrated Analysis (`domain/analyzer.py`)](#54-orchestrated-analysis)
6. [MCP Tool Registration (`src/modules/phishing/mcp/tools.py`)](#6-mcp-tool-registration)
7. [HTTP Server (`src/server.py`)](#7-http-server)
8. [MCP Tools Reference](#8-mcp-tools-reference)
9. [Data Models](#9-data-models)
10. [External APIs](#10-external-apis)
11. [Docker Infrastructure](#11-docker-infrastructure)
12. [Configuration Reference](#12-configuration-reference)
13. [Known Constraints and Design Decisions](#13-known-constraints-and-design-decisions)
14. [Retraining the Image Fraud Model](#14-retraining-the-image-fraud-model)

---

## 1. Overview

`phishing-detector` is a Model Context Protocol (MCP) server that exposes four tools for detecting phishing and financial fraud in emails targeting Chilean users. It is written in Python using FastMCP and exposes its endpoint over StreamableHTTP transport, making it consumable by any MCP-capable client (Claude Desktop, Claude Code, custom agents).

The analysis pipeline combines three independent data sources — static regex patterns, RDAP/WHOIS lookups, and the CMF Chile financial registry — and feeds their results into a Claude Sonnet model that produces a structured risk report in Spanish.

---

## 2. Architecture

```
MCP Client (Claude Desktop / Claude Code / agent)
        │
        │  StreamableHTTP  POST /mcp
        ▼
┌─────────────────────────────────────────────┐
│  Docker: phishing-detector-mcp              │
│  python:3.11-slim, port 3000                │
│                                             │
│  Starlette ASGI                             │
│  ├── GET /          → health JSON           │
│  └── /mcp           → FastMCP ASGI app      │
│       ├── analyze_email_tool                │
│       │     ├── check_email_patterns()      │  (local, no I/O)
│       │     ├── lookup_domain_whois()  ──►  │  rdap.org
│       │     ├── verify_cmf_entity()   ──►  │  api.cmfchile.cl
│       │     └── claude.messages.create ──► │  Anthropic API
│       ├── lookup_domain_whois_tool          │
│       ├── verify_cmf_entity_tool            │
│       └── check_email_patterns_tool         │
└─────────────────────────────────────────────┘
        │
        │  reverse proxy
        ▼
┌────────────────────────────────────┐
│  Docker: phishing-detector-tunnel  │
│  cloudflare/cloudflared            │
│  → https://<random>.trycloudflare.com
└────────────────────────────────────┘
```

The two Docker services share a single user-defined bridge network (`mcp-net`). Cloudflared only starts once `mcp-server` passes its healthcheck (`service_healthy` condition), ensuring the tunnel never points at a broken server.

---

## 3. Project Structure

```
.
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── src/
│   ├── server.py                          # Starlette app + uvicorn entrypoint
│   ├── core/
│   │   ├── types.py                       # Shared Pydantic models
│   │   └── claude.py                      # Singleton Anthropic client
│   └── modules/
│       └── phishing/
│           ├── domain/
│           │   ├── analyzer.py            # Orchestrates full analysis pipeline
│           │   ├── patterns.py            # Static regex pattern engine
│           │   ├── whois.py               # RDAP lookup via rdap.org
│           │   └── cmf.py                 # CMF Chile institution registry
│           └── mcp/
│               └── tools.py              # MCP tool registrations
```

---

## 4. Core Modules

### 4.1 Shared Types

**File:** `src/core/types.py`

Defines all Pydantic models used as the canonical data contract between layers. No business logic lives here.

| Model | Purpose |
|---|---|
| `FraudReport` | Final structured output from `analyze_email` |
| `WhoisData` | Parsed RDAP response for a domain |
| `CmfEntityResult` | Result of fuzzy-matching against the CMF registry |
| `PatternCheckResult` | Aggregated output from the static pattern engine |

```python
class FraudReport(BaseModel):
    riskScore: int                                      # 0–100
    riskLevel: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    indicators: list[str]
    domainAge: Optional[str] = None                    # ISO date string
    domainCountry: Optional[str] = None
    cmfRegistered: Optional[bool] = None
    explanation: str
    recommendations: list[str]
```

### 4.2 Anthropic Client Factory

**File:** `src/core/claude.py`

Provides a module-level singleton `Anthropic` client. The instance is created on first call and reused for all subsequent requests, avoiding repeated SDK initialization overhead inside hot paths.

```python
def get_anthropic_client() -> Anthropic:
    global _client
    if _client is None:
        _client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    return _client
```

---

## 5. Phishing Domain Logic

### 5.1 Static Pattern Detection

**File:** `src/modules/phishing/domain/patterns.py`

Purely synchronous, zero-I/O engine that inspects email content, subject, and sender address using compiled regular expressions and keyword lists. It is designed to be fast and run offline.

**Detection signals:**

| Signal key | Trigger condition |
|---|---|
| `urgency_language` | Match against 15 urgency keywords (Spanish + English) |
| `suspicious_tld` | Sender domain ends in `.xyz`, `.top`, `.club`, `.work`, `.click`, `.link`, `.site`, `.online`, `.tech`, or `.info` |
| `sender_spoofing` | Display name matches a Chilean institution but the actual domain does not |
| `institution_mismatch` | Body mentions a known institution but sender domain is not its official domain |
| `suspicious_links` | Links containing raw IP addresses, known URL shorteners, or domains with ≥30 character subdomains |
| `excessive_links` | More than 5 hyperlinks in the body |
| `unicode_lookalike` | Non-ASCII characters in subject or sender (homograph attack indicator) |
| `credential_request` | Keywords like `contraseña`, `clave`, `rut`, `cvv`, `pin`, `número de tarjeta` |
| `malformed_sender` | Sender address contains no `@` character |

**Output:** `PatternCheckResult` with a list of matched signal keys, human-readable Spanish detail strings, and a count.

### 5.2 WHOIS Lookup

**File:** `src/modules/phishing/domain/whois.py`

Queries the [RDAP](https://rdap.org) protocol (JSON-based successor to WHOIS) via `rdap.org/domain/{domain}`. Uses `httpx.AsyncClient` with an 8-second timeout. All errors are caught and return an empty `WhoisData` — the caller is never blocked by a lookup failure.

**Domain cleaning:** Strips `http://`, `https://`, and any path component before querying, so raw sender domains and full URLs are handled identically.

**Parsed fields:** registrar (from vCard `fn` entry of the registrar entity), registration and expiry dates (ISO 8601 → `YYYY-MM-DD`), registrant country (from vCard `adr` entry), domain status string, and nameserver list.

### 5.3 CMF Verification

**File:** `src/modules/phishing/domain/cmf.py`

Queries the CMF Chile public API (`api.cmfchile.cl/api-sbifv3/recursos_api/instituciones`) to verify whether a named financial institution is registered with Chile's financial regulator. Requires `CMF_API_KEY` in the environment; returns `found=False` gracefully if the key is absent or the API is unreachable.

**Fuzzy matching algorithm** (`_match_score`): Normalizes both strings to lowercase NFD without diacritics, then applies four tiers:

1. Exact match → `1.0`
2. Query is substring of candidate → `0.9`
3. Candidate is substring of query → `0.8`
4. Word-level overlap: `matched_words / total_query_words` (only words > 2 chars)

A result is accepted when the score is ≥ 0.5. The best-scoring institution across the full registry list is returned.

### 5.4 Orchestrated Analysis

**File:** `src/modules/phishing/domain/analyzer.py`

Implements `analyze_email()`, the top-level coroutine that drives the full pipeline:

1. **Base64 decode attempt** — if the email content looks like a base64 blob (>100 chars, matches charset), decodes it before analysis.
2. **Static patterns** — runs `check_email_patterns()` synchronously.
3. **Domain extraction** — parses sender domain via regex; extracts mentioned institution names from a hardcoded list.
4. **Concurrent I/O** — fires `lookup_domain_whois()` and `verify_cmf_entity()` in parallel via `asyncio.gather()`. If either input is absent (no sender domain, no institution mentioned), a no-op `asyncio.sleep(0)` is used as a placeholder so `gather` always receives exactly two awaitables.
5. **Context assembly** — builds a structured Spanish-language prompt from all gathered data: WHOIS summary, CMF finding, and pattern details.
6. **Claude call** — calls `claude-sonnet-4-5` with the system prompt marked as `ephemeral` for prompt caching. Max tokens: 1500.
7. **JSON extraction** — extracts the JSON block from the model response via regex (handles both fenced code blocks and bare JSON objects). Falls back to a partial result if parsing fails.

**Prompt caching:** The system prompt (static across all calls) is sent with `"cache_control": {"type": "ephemeral"}`. This means the first call in a session incurs a full token cost for the system prompt; subsequent calls within the cache TTL pay only for the user turn.

---

## 6. MCP Tool Registration

**File:** `src/modules/phishing/mcp/tools.py`

Exports `register_phishing_tools(mcp: FastMCP)` which closes over the `FastMCP` instance and registers four tools using the `@mcp.tool()` decorator. The function is called once at module import time in `server.py`.

All tool functions are thin adapters: they marshal string parameters from the MCP wire format, delegate to the domain layer, and serialize the result to JSON or a Pydantic model dump.

The `PHISHING_TOOL_NAMES` constant is a plain list used in the health endpoint response to advertise available tools without introspecting the FastMCP registry at runtime.

---

## 7. HTTP Server

**File:** `src/server.py`

Assembles a `Starlette` ASGI application with two routes:

| Route | Handler | Notes |
|---|---|---|
| `GET /` | `health()` | Returns JSON with server name, version, tool list, transport info |
| `/mcp` (all methods) | FastMCP ASGI app | Mounted via `mcp.streamable_http_app()` |

The `FastMCP` instance is configured with `stateless_http=True`, which disables session state between requests. This is appropriate for the server's use case: each tool invocation is fully self-contained.

When invoked as `__main__` (i.e., `python -m src.server`), uvicorn is started with `loop="asyncio"` to explicitly use the standard library event loop. This prevents native C extension event loops (such as uvloop) from being loaded even if they are present in the environment.

---

## 8. MCP Tools Reference

### `analyze_email`

Full pipeline analysis. Runs pattern detection, WHOIS lookup, CMF verification, and Claude AI in sequence, returning a JSON risk report.

**Input parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `email_content` | `string` | yes | Raw email body (plain text or base64) |
| `sender_email` | `string` | no | Full sender address, e.g. `"Name <user@domain.com>"` |
| `subject` | `string` | no | Email subject line |

**Output:** JSON-serialized `FraudReport` object (see [Data Models](#9-data-models)).

**Risk scale:**

| Score range | Level | Meaning |
|---|---|---|
| 0–25 | LOW | Likely legitimate |
| 26–50 | MEDIUM | Warning signs, proceed with caution |
| 51–75 | HIGH | Probable phishing or fraud |
| 76–100 | CRITICAL | Confirmed phishing or obvious scam |

---

### `lookup_domain_whois`

Single RDAP lookup. Does not call Claude.

**Input parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `domain` | `string` | yes | Domain name or full URL |

**Output:** JSON-serialized `WhoisData` object.

---

### `verify_cmf_entity`

Single CMF registry lookup. Does not call Claude. Returns `found=false` if `CMF_API_KEY` is not set.

**Input parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `institution_name` | `string` | yes | Name of the institution to look up |

**Output:** JSON-serialized `CmfEntityResult` object.

---

### `check_email_patterns`

Static analysis only. No network calls, no API keys required. Useful for quick pre-screening.

**Input parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `email_content` | `string` | yes | Raw email body |
| `sender_email` | `string` | no | Full sender address |
| `subject` | `string` | no | Email subject line |

**Output:** JSON-serialized `PatternCheckResult` object.

---

## 9. Data Models

### `WhoisData`

```python
domain: str
registrar: Optional[str]       # Registrar display name
created: Optional[str]         # Registration date (YYYY-MM-DD)
expires: Optional[str]         # Expiry date (YYYY-MM-DD)
country: Optional[str]         # Registrant country code
status: Optional[str]          # Domain status string (comma-separated)
nameservers: Optional[list[str]]
```

### `CmfEntityResult`

```python
found: bool
entityName: Optional[str]      # Official name in CMF registry
entityType: Optional[str]      # e.g. "Banco", "Institución Financiera"
matchScore: Optional[float]    # 0.0–1.0 fuzzy match confidence
```

### `PatternCheckResult`

```python
patterns: list[str]            # Signal keys, e.g. ["urgency_language", "suspicious_tld"]
suspiciousCount: int           # len(patterns)
details: list[str]             # Human-readable Spanish descriptions
```

### `FraudReport`

```python
riskScore: int                 # 0–100
riskLevel: str                 # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
indicators: list[str]          # Bullet-point indicators from Claude
domainAge: Optional[str]       # Forwarded from WhoisData.created
domainCountry: Optional[str]   # Forwarded from WhoisData.country
cmfRegistered: Optional[bool]  # Forwarded from CmfEntityResult.found
explanation: str               # Plain-Spanish explanation for non-technical users
recommendations: list[str]     # Concrete action steps in Spanish
```

---

## 10. External APIs

### Anthropic Claude API

- **Endpoint:** Anthropic SDK default (`api.anthropic.com`)
- **Model:** `claude-sonnet-4-5`
- **Auth:** `ANTHROPIC_API_KEY` environment variable
- **Caching:** System prompt sent with `cache_control: ephemeral`
- **Max output tokens:** 1500

### rdap.org (WHOIS)

- **Endpoint:** `https://rdap.org/domain/{domain}`
- **Auth:** None — public service
- **Timeout:** 8 seconds
- **Failure mode:** Returns empty `WhoisData` (domain field only)

### CMF Chile API

- **Endpoint:** `https://api.cmfchile.cl/api-sbifv3/recursos_api/instituciones`
- **Auth:** `CMF_API_KEY` query parameter — free registration at [api.cmfchile.cl](https://api.cmfchile.cl)
- **Timeout:** 8 seconds
- **Failure mode:** Returns `CmfEntityResult(found=False)` — any error or missing key is silently swallowed

---

## 11. Docker Infrastructure

### Services

**`mcp-server`** (`phishing-detector-mcp`)

- Base image: `python:3.11-slim`
- Build: copies `requirements.txt` first (layer caching), then `src/`
- Port: `3000` (host and container)
- Healthcheck: Python socket connection to `localhost:3000` — no curl dependency
  - `start_period`: 20s, `interval`: 10s, `timeout`: 5s, `retries`: 5
- Restart policy: `unless-stopped`

**`cloudflared`** (`phishing-detector-tunnel`)

- Image: `cloudflare/cloudflared:latest`
- Mode: quick tunnel (`--no-autoupdate --url http://mcp-server:3000`)
- Start condition: `depends_on: mcp-server: condition: service_healthy`
- Restart policy: `unless-stopped`
- Public URL: printed in container logs on startup

Both services are attached to a user-defined bridge network `mcp-net`. This ensures DNS resolution between containers by name (`mcp-server`) regardless of Docker Compose project naming conventions.

### Image naming caveat

When using the legacy `docker-compose` CLI (v1), the built image is tagged `{project_underscored}_{service}:latest` (e.g., `mcp-adk-container-1_mcp-server:latest`). `docker build -t` uses the argument verbatim. If you rebuild manually with `docker build`, retag the result to match the compose name before running `docker-compose up`:

```bash
docker build -t mcp-adk-container-1_mcp-server .
```

Or use Docker Compose v2 (`docker compose build`) which handles this automatically.

---

## 12. Configuration Reference

All configuration is via environment variables, loaded from `.env` at startup by `python-dotenv`.

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | **Yes** | — | Anthropic API key. Without this the server starts but `analyze_email` will raise on every call. |
| `CMF_API_KEY` | No | — | CMF Chile API key. Without this, `verify_cmf_entity` always returns `found=false`. |
| `PORT` | No | `3000` | TCP port uvicorn listens on. Must match the port in `docker-compose.yml`. |

`.env.example` contains commented templates for all variables. Copy it to `.env` and fill in at minimum `ANTHROPIC_API_KEY`.

---

## 13. Known Constraints and Design Decisions

**No uvloop.** The container previously crashed with exit code 139 (SIGSEGV) due to uvloop (a C extension installed by `uvicorn[standard]`). The fix is plain `uvicorn` in `requirements.txt` plus `loop="asyncio"` in `uvicorn.run()`. Do not re-add `uvicorn[standard]` without testing in the exact Docker environment first.

**Stateless HTTP.** `FastMCP` is configured with `stateless_http=True`. There is no session affinity, no in-memory state between requests, and no streaming mid-call. Each tool invocation is fully independent.

**Singleton Anthropic client.** The `Anthropic` instance is module-level and reused across requests. The SDK handles connection pooling internally. This avoids SDK initialization overhead on each request.

**No retry logic on external calls.** WHOIS and CMF failures return empty results silently. This is intentional: the server must never block an MCP tool call due to a third-party outage. The Claude analysis still runs with whatever data was gathered.

**Quick Cloudflare tunnel.** The tunnel URL changes on every restart and has no uptime guarantee. For production use, replace the `cloudflared` service with a named tunnel configured via a Cloudflare account and `credentials-file`.

**CMF fuzzy match threshold.** The `_match_score` function accepts matches ≥ 0.5. This was chosen to catch common abbreviations ("Banco Chile" vs "Banco de Chile") while avoiding false positives. Lowering the threshold increases recall but risks matching unrelated institutions.

**Base64 email support.** `analyze_email` attempts to decode the email body as base64 if it is longer than 100 characters and matches the base64 charset. This covers some email clients that encode the body. The heuristic is conservative — it requires the string to match `^[A-Za-z0-9+/=\n]+$` — so plain-text content with punctuation is never mistakenly decoded.

---

## 14. Retraining the Image Fraud Model

"Retraining" in this system means **rebuilding the FAISS index** from the fraud image dataset. The CLIP encoder weights are never updated — only the reference embedding library changes. You need to retrain when:

- New CSIRT bulletins have been downloaded and extracted (`dataset/csirt_extracted/` has grown).
- The artifacts were deleted or corrupted.
- You want to use a different `top_k` default or CLIP model variant.

### Prerequisites

All steps run inside the `csirt-img-ml-model` repo, **not** inside the MCP container.

```bash
cd /path/to/csirt-img-ml-model
python3.9 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 1 — (Optional) Extract new images from PDFs

Skip this step if `dataset/csirt_extracted/` is already populated and no new PDFs have been added.

```bash
# Place new CSIRT bulletin PDFs into dataset/csirt_pdf/ first, then:
python extract_fraud_images.py
# Input:  dataset/csirt_pdf/          (CSIRT bulletin PDFs)
# Output: dataset/csirt_extracted/    (image + .txt pairs)
```

Each PDF page that contains a CSIRT incident table produces one `<stem>_p<NN>_<idx>.jpeg` and a companion `<stem>_p<NN>_<idx>.txt` with the parsed incident metadata.

### Step 2 — Rebuild the FAISS index

```bash
python train.py
# Optional flags:
#   --dataset   dataset/csirt_extracted   (default)
#   --artifacts fraud_model/artifacts     (default)
#   --batch-size 32                       (images per CLIP batch)
```

`train.py` performs the following:

1. Discovers all `*.jpeg` / `*.png` files under `--dataset` that have a paired `.txt`.
2. Loads the pre-trained CLIP `ViT-B-32-quickgelu` (OpenAI weights, auto-downloaded ~340 MB on first run).
3. Embeds all images in batches of `--batch-size`, L2-normalises each 512-dim vector.
4. Builds a `faiss.IndexFlatIP` and adds all embeddings.
5. Parses every `.txt` into an `IncidentMetadata` record (preserving index alignment).
6. Writes three artifacts:

| Artifact | Size | Description |
|---|---|---|
| `fraud_model/artifacts/index.faiss` | ~7.7 MB | FAISS flat inner-product index |
| `fraud_model/artifacts/metadata.json` | ~3.0 MB | JSON array of incident records (aligned to index rows) |
| `fraud_model/artifacts/embeddings.npy` | ~7.7 MB | Raw NumPy backup of the embedding matrix |

Runtime on a single CPU core is approximately 9 minutes for 3,764 images.

### Step 3 — Copy the new artifacts into the MCP container

After rebuilding, the three artifact files must be available to the running Docker container. There are two ways to do this:

**A. Rebuild the Docker image (recommended for production)**

The Dockerfile already copies `csirt-img-ml-model/fraud_model/` (including `artifacts/`) into the image at build time. Rebuild from the `ANALYSISARMY` parent directory:

```bash
cd /path/to/ANALYSISARMY
docker compose -f mcp-adk-container-1/docker-compose.yml build mcp-server
docker compose -f mcp-adk-container-1/docker-compose.yml up -d
```

**B. Mount the artifacts directory as a volume (development)**

Add a `volumes` entry to the `mcp-server` service in `docker-compose.yml` to bind-mount the live artifact directory:

```yaml
services:
  mcp-server:
    # … existing config …
    volumes:
      - ../csirt-img-ml-model/fraud_model/artifacts:/app/fraud_model/artifacts:ro
```

With this mount, rerunning `train.py` on the host immediately makes the new artifacts available without rebuilding the image. Restart the container to reload the singleton `FraudDetector`:

```bash
docker compose -f mcp-adk-container-1/docker-compose.yml restart mcp-server
```

### Step 4 — Verify

Confirm the new index is loaded by checking the health endpoint:

```bash
curl http://localhost:3000/ | python3 -m json.tool
```

Then call `analyze_fraud_image` with a known fraud screenshot from the dataset and confirm the top match has `similarity` ≈ 1.0 and `risk_level` = `CRITICAL`.

### Adding images incrementally (without full retraining)

If you only have a small number of new confirmed fraud images, you can append them to the existing index without reprocessing the full dataset:

```python
from fraud_model.embedder import FraudImageEmbedder
from fraud_model.metadata import parse_txt
import faiss, json, numpy as np

ARTIFACTS = "fraud_model/artifacts"

embedder  = FraudImageEmbedder()
index     = faiss.read_index(f"{ARTIFACTS}/index.faiss")
metadata  = json.load(open(f"{ARTIFACTS}/metadata.json"))

# Paths to new image files (each must have a paired .txt)
new_images = ["/path/to/new_fraud_01.jpeg", "/path/to/new_fraud_02.jpeg"]
new_txts   = ["/path/to/new_fraud_01.txt",  "/path/to/new_fraud_02.txt"]

new_embs = embedder.embed_batch(new_images)   # shape (N, 512), L2-normalised
index.add(new_embs)
faiss.write_index(index, f"{ARTIFACTS}/index.faiss")

for txt in new_txts:
    metadata.append(parse_txt(txt).to_dict())
json.dump(metadata, open(f"{ARTIFACTS}/metadata.json", "w"), ensure_ascii=False, indent=2)

# Update the NumPy backup (optional)
all_embs = np.vstack([
    np.load(f"{ARTIFACTS}/embeddings.npy"),
    new_embs,
])
np.save(f"{ARTIFACTS}/embeddings.npy", all_embs)
```

> **Important:** The FAISS index row order and the `metadata.json` array order must always stay in sync. Only append to both — never insert or reorder rows in an existing index.
