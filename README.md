# mcp-adk-container

**AnalysisArmy — Claude Impact Lab Chile 2026**
Track: Ciberseguridad Ciudadana

MCP server for phishing and financial fraud detection in emails. Runs in Docker, exposed publicly via Cloudflare Tunnel. Any MCP-compatible client (Claude Desktop, Claude Code, custom agents) can connect and invoke the analysis tools.

Two fully functional implementations are available on separate branches:

| Branch | Stack | Transport |
|---|---|---|
| [`adk-ts`](../../tree/adk-ts) | TypeScript · Node 20 · `@modelcontextprotocol/sdk` · Express | StreamableHTTP |
| [`adk-python`](../../tree/adk-python) | Python 3.11 · FastMCP (`mcp[cli]`) · Starlette · uvicorn | StreamableHTTP |

---

## Architecture

```
Claude Desktop / Claude Code / Any MCP Client
        │  StreamableHTTP   https://xxx.trycloudflare.com/mcp
        ▼
┌──────────────────────────────────────────────────┐
│  Docker Compose                                  │
│                                                  │
│  mcp-server  (port 3000)                        │
│  ├── analyze_email      → Claude API (Sonnet)   │
│  ├── lookup_domain_whois→ rdap.org (free)        │
│  ├── verify_cmf_entity  → api.cmfchile.cl        │
│  └── check_email_patterns (static analysis)     │
│                                                  │
│  cloudflared → free public URL                  │
└──────────────────────────────────────────────────┘
```

---

## MCP Tools

| Tool | Description |
|---|---|
| `analyze_email` | Full analysis: Claude AI + WHOIS + CMF. Returns risk score 0–100 + structured report |
| `lookup_domain_whois` | RDAP lookup for the sender domain (registrar, age, country) |
| `verify_cmf_entity` | Checks if a financial institution is in the CMF Chile registry |
| `check_email_patterns` | Static phishing pattern detection — no API keys required |

---

## Quick Start

### 1. Pick an implementation

```bash
# TypeScript (Node 20)
git checkout adk-ts

# Python (3.11 + FastMCP)
git checkout adk-python
```

### 2. Configure environment

```bash
cp .env.example .env
# Add ANTHROPIC_API_KEY (required)
# Add CMF_API_KEY (optional — verify_cmf_entity tool)
```

### 3. Run

```bash
docker compose up --build

# Get the public tunnel URL:
docker compose logs cloudflared
# → "Your quick Tunnel... https://xxx.trycloudflare.com"
```

### 4. Connect to Claude Code

```bash
claude mcp add phishing-detector https://xxx.trycloudflare.com/mcp --transport http
```

### 5. Verify

```bash
curl http://localhost:3000/     # health check
curl http://localhost:3000/mcp  # MCP endpoint
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Claude API key for `analyze_email` |
| `CMF_API_KEY` | No | CMF Chile API key for `verify_cmf_entity` |
| `PORT` | No | Server port (default: 3000) |

---

## Implementation Details

### TypeScript (`adk-ts` branch)
- **MCP SDK**: `@modelcontextprotocol/sdk` — `McpServer` + `StreamableHTTPServerTransport`
- **HTTP**: Express 4, stateless handler — new server instance per request
- **Build**: Multi-stage Docker (TypeScript → compiled JS)
- **AI**: `@anthropic-ai/sdk` with ephemeral prompt caching on system prompt

### Python (`adk-python` branch)
- **MCP SDK**: `mcp[cli]` (FastMCP) — `mcp.streamable_http_app()` returns Starlette ASGI app
- **HTTP**: Starlette + uvicorn, parent app mounts `/mcp` + health at `/`
- **Types**: Pydantic models for all domain objects
- **AI**: `anthropic` SDK with ephemeral prompt caching; `asyncio.gather` for parallel lookups

Both branches implement identical tool schemas, identical Claude prompt design, and identical Docker + Cloudflare tunnel setup.

---

## Team

AnalysisArmy — Francisco Aranda, Oscar Fernández, Magdiel, Sergio Miranda
