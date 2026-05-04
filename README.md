# mcp-adk-container — Python / FastMCP

**AnalysisArmy — Claude Impact Lab Chile 2026 PoC**

MCP server implementado en **Python con FastMCP** para detección de phishing y fraude financiero en correos. Corre en Docker y se expone mediante Cloudflare Tunnel.

## Quick Notes

cd mcp-adk-container-1
docker-compose up -d --build
docker logs -f phishing-detector-mcp


## Arquitectura

```
Claude Desktop / Claude Code / Any MCP Client
        │  StreamableHTTP   https://xxx.trycloudflare.com/mcp
        ▼
┌──────────────────────────────────────────────────┐
│  Docker Compose                                  │
│                                                  │
│  mcp-server (Python 3.11 + FastMCP, port 3000)  │
│  ├── analyze_email      → Claude API (Sonnet)   │
│  ├── lookup_domain_whois→ rdap.org (gratuito)   │
│  ├── verify_cmf_entity  → api.cmfchile.cl        │
│  └── check_email_patterns (análisis estático)   │
│                                                  │
│  cloudflared → URL pública gratuita              │
└──────────────────────────────────────────────────┘
```

## Herramientas MCP disponibles

| Tool | Descripción |
|---|---|
| `analyze_email` | Análisis completo con Claude + WHOIS + CMF. Retorna score 0-100 + informe |
| `lookup_domain_whois` | Consulta RDAP del dominio remitente |
| `verify_cmf_entity` | Verifica si una institución está en el registro CMF Chile |
| `check_email_patterns` | Detección estática de patrones de phishing (sin API keys) |

## Setup rápido

### 1. Configurar variables

```bash
cp .env.example .env
# Editar .env y agregar ANTHROPIC_API_KEY
```

### 2. Levantar con Docker Compose

```bash
docker compose up --build

# Obtener la URL pública del tunnel:
docker compose logs cloudflared
# → "Your quick Tunnel... https://xxx.trycloudflare.com"

# Ver logs del servidor MCP en tiempo real:
docker-compose logs -f mcp-server

# Alternativa directa por nombre de contenedor:
docker logs -f phishing-detector-mcp
```

### 3. Conectar a Claude Code

```bash
claude mcp add phishing-detector https://xxx.trycloudflare.com/mcp --transport http
```

### 4. Verificar

```bash
curl http://localhost:3000/         # health check
curl http://localhost:3000/mcp      # MCP endpoint
```

## Desarrollo local

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # agregar ANTHROPIC_API_KEY
python -m src.server
```

## Stack

- **Runtime**: Python 3.11
- **MCP**: FastMCP (`mcp[cli]`) — StreamableHTTP transport
- **AI**: `anthropic` — claude-sonnet-4-5 con prompt caching
- **HTTP async**: `httpx`
- **WHOIS**: rdap.org (gratuito, sin API key)
- **CMF**: api.cmfchile.cl (gratuito, requiere registro)
- **Tunnel**: cloudflare/cloudflared quick tunnel (sin cuenta)
- **Container**: Docker python:3.11-slim

## Equipo

AnalysisArmy — Francisco Aranda, Oscar Fernández, Magdiel, Sergio Miranda
