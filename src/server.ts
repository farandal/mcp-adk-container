import express from "express";
import cors from "cors";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { registerTools, TOOL_NAMES } from "./tools/registry.js";

const PORT = Number(process.env.PORT ?? 3000);

function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "phishing-detector",
    version: "1.0.0",
  });
  registerTools(server);
  return server;
}

async function main(): Promise<void> {
  const app = express();

  app.use(cors());
  app.use(express.json());

  // Health check
  app.get("/", (_req, res) => {
    res.json({
      status: "ok",
      name: "phishing-detector MCP server",
      version: "1.0.0",
      tools: TOOL_NAMES,
      mcp_endpoint: "/mcp",
      transport: "StreamableHTTP",
    });
  });

  // StreamableHTTP MCP endpoint — each request creates its own stateless transport
  // so the server scales horizontally without sticky sessions
  app.all("/mcp", async (req, res) => {
    const server = createMcpServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
    });

    res.on("close", () => {
      void transport.close();
      void server.close();
    });

    try {
      await server.connect(transport);
      // Pass req.body so the transport doesn't try to re-read the consumed stream
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("[server] MCP handler error:", err);
      if (!res.headersSent) {
        res.status(500).json({ error: "Internal server error" });
      }
    }
  });

  const httpServer = app.listen(PORT, () => {
    console.log(`[server] phishing-detector MCP server running on port ${PORT}`);
    console.log(`[server] Health:  http://localhost:${PORT}/`);
    console.log(`[server] MCP:     http://localhost:${PORT}/mcp`);
  });

  // Graceful shutdown for Docker SIGTERM
  const shutdown = (): void => {
    console.log("[server] Shutting down...");
    httpServer.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err) => {
  console.error("[server] Fatal error:", err);
  process.exit(1);
});
