# mcp-adk-container

**AnalysisArmy — Claude Impact Lab Chile 2026 PoC**

MCP server (TypeScript) para detección de phishing y fraude financiero en correos electrónicos. Corre en Docker y se expone al internet mediante Cloudflare Tunnel, listo para conectarse como servidor MCP remoto desde Claude Desktop o Claude Code.

## Arquitectura

```
Claude Desktop / Claude Code / Any MCP Client
        │  StreamableHTTP   https://xxx.trycloudflare.com/mcp
        ▼
┌──────────────────────────────────────────────────┐
│  Docker Compose                                  │
│                                                  │
│  mcp-server (Node 20 + TypeScript, port 3000)   │
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

### 1. Clonar y configurar variables

```bash
cp .env.example .env
# Editar .env y agregar ANTHROPIC_API_KEY
```

### 2. Levantar con Docker Compose

```bash
docker compose up --build
```

Obtener la URL pública:

```bash
docker compose logs cloudflared
# Buscar línea: "Your quick Tunnel has been created! Visit it at: https://xxx.trycloudflare.com"
```

### 3. Conectar a Claude Code

```bash
claude mcp add phishing-detector https://xxx.trycloudflare.com/mcp --transport http
```

O en Claude Desktop, agregar a `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "phishing-detector": {
      "url": "https://xxx.trycloudflare.com/mcp",
      "transport": "http"
    }
  }
}
```

### 4. Verificar la conexión

```bash
# Health check local
curl http://localhost:3000/

# En Claude Code
/mcp
```

## Desarrollo local (sin Docker)

```bash
npm install
cp .env.example .env   # agregar ANTHROPIC_API_KEY
npm run dev            # tsx watch — hot reload
```

```bash
# Test manual del endpoint MCP
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}'
```

## Ejemplo de uso en Claude

Con el MCP conectado, simplemente pedir a Claude:

> "Analiza este correo sospechoso que recibí del SII:
> De: notificaciones@sii-chile-oficial.xyz
> Asunto: URGENTE: Su RUT ha sido bloqueado — verifique ahora
> ..."

Claude llamará automáticamente a `analyze_email` y retornará un informe estructurado.

## Stack

- **Runtime**: Node.js 20 + TypeScript (ESM)
- **MCP SDK**: `@modelcontextprotocol/sdk` v1 — StreamableHTTP transport
- **AI**: `@anthropic-ai/sdk` — claude-sonnet-4-5 con prompt caching
- **WHOIS**: rdap.org (gratuito, sin API key)
- **CMF**: api.cmfchile.cl (gratuito, requiere registro)
- **Tunnel**: cloudflare/cloudflared quick tunnel (sin cuenta)
- **Container**: Docker multi-stage build (node:20-slim)

## Equipo
AnalysisArmy — Francisco Aranda, Oscar Fernández, Magdiel, Sergio Miranda y Claude 4.6.
