import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { analyzeEmail } from "./analyzeEmail.js";
import { lookupDomainWhois } from "./whoisLookup.js";
import { verifyCmfEntity } from "./cmfVerify.js";
import { checkEmailPatterns } from "./checkEmailPatterns.js";

export function registerTools(server: McpServer): void {
  server.registerTool(
    "analyze_email",
    {
      title: "Analyze Suspicious Email",
      description:
        "Analiza un correo electrónico sospechoso para detectar phishing o fraude financiero. " +
        "Combina análisis de patrones, verificación WHOIS del dominio, consulta a CMF Chile " +
        "y análisis con IA (Claude). Retorna un informe estructurado con score de riesgo, " +
        "indicadores y recomendaciones en español.",
      inputSchema: {
        emailContent: z
          .string()
          .describe("Contenido completo del correo (texto plano o base64)"),
        senderEmail: z
          .string()
          .optional()
          .describe("Dirección del remitente, ej: soporte@banco-falso.xyz"),
        subject: z
          .string()
          .optional()
          .describe("Asunto del correo"),
      },
    },
    async ({ emailContent, senderEmail, subject }) => {
      const report = await analyzeEmail({ emailContent, senderEmail, subject });
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(report, null, 2),
          },
        ],
      };
    }
  );

  server.registerTool(
    "lookup_domain_whois",
    {
      title: "Domain WHOIS Lookup",
      description:
        "Consulta información WHOIS de un dominio usando RDAP (Registration Data Access Protocol). " +
        "Retorna registrador, fecha de creación, país y estado del dominio.",
      inputSchema: {
        domain: z
          .string()
          .describe("Dominio a consultar, ej: banco-falso.xyz o https://banco-falso.xyz/login"),
      },
    },
    async ({ domain }) => {
      const data = await lookupDomainWhois(domain);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(data, null, 2),
          },
        ],
      };
    }
  );

  server.registerTool(
    "verify_cmf_entity",
    {
      title: "Verify CMF Chile Entity",
      description:
        "Verifica si una institución financiera está registrada en la CMF (Comisión para el " +
        "Mercado Financiero de Chile). Útil para detectar suplantación de bancos u otras " +
        "entidades reguladas. Requiere CMF_API_KEY configurada.",
      inputSchema: {
        institutionName: z
          .string()
          .describe("Nombre de la institución a verificar, ej: Banco de Chile, Santander"),
      },
    },
    async ({ institutionName }) => {
      const result = await verifyCmfEntity(institutionName);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    }
  );

  server.registerTool(
    "check_email_patterns",
    {
      title: "Check Email Patterns",
      description:
        "Análisis estático de patrones de phishing en un correo: urgencia, TLDs sospechosos, " +
        "suplantación de instituciones chilenas, solicitud de credenciales, enlaces sospechosos. " +
        "No requiere llamadas externas ni API keys.",
      inputSchema: {
        emailContent: z.string().describe("Contenido del correo a analizar"),
        senderEmail: z.string().optional().describe("Dirección del remitente"),
        subject: z.string().optional().describe("Asunto del correo"),
      },
    },
    async ({ emailContent, senderEmail, subject }) => {
      const result = checkEmailPatterns(emailContent, senderEmail, subject);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    }
  );
}

export const TOOL_NAMES = [
  "analyze_email",
  "lookup_domain_whois",
  "verify_cmf_entity",
  "check_email_patterns",
] as const;
