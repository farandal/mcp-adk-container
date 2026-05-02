import Anthropic from "@anthropic-ai/sdk";
import type { FraudReport, AnalyzeEmailInput } from "../types/index.js";
import { lookupDomainWhois } from "./whoisLookup.js";
import { verifyCmfEntity } from "./cmfVerify.js";
import { checkEmailPatterns } from "./checkEmailPatterns.js";

const SYSTEM_PROMPT = `Eres un experto en ciberseguridad financiera chilena. Tu tarea es analizar correos electrónicos potencialmente fraudulentos y generar informes de riesgo detallados, comprensibles para ciudadanos no técnicos.

Contexto regulatorio chileno:
- CMF (Comisión para el Mercado Financiero): regula bancos, seguros, valores
- SII (Servicio de Impuestos Internos): impuestos, RUT, facturas electrónicas
- SERNAC: protección al consumidor
- BancoEstado, Banco de Chile, Santander, BCI, Scotiabank, Itaú son los principales bancos
- Transbank maneja pagos con tarjeta
- Las instituciones oficiales NUNCA solicitan contraseñas, datos de tarjeta ni claves por correo

Tu respuesta debe ser ÚNICAMENTE un objeto JSON válido con esta estructura exacta:
{
  "riskScore": <número 0-100>,
  "riskLevel": <"LOW" | "MEDIUM" | "HIGH" | "CRITICAL">,
  "indicators": [<lista de indicadores técnicos en español>],
  "explanation": "<explicación clara en español para una persona sin conocimientos técnicos, máximo 3 párrafos>",
  "recommendations": [<lista de recomendaciones concretas en español>]
}

Escala de riesgo:
- 0-25: LOW — correo probablemente legítimo
- 26-50: MEDIUM — señales de alerta, proceder con cautela
- 51-75: HIGH — probable phishing o fraude
- 76-100: CRITICAL — phishing confirmado o estafa evidente`;

function extractDomainFromEmail(email: string): string | null {
  const match = email.match(/@([^>@\s]+)/);
  return match ? match[1].toLowerCase() : null;
}

function extractMentionedInstitutions(content: string): string[] {
  const patterns = [
    "banco de chile", "bancochile", "bancoestado", "banco estado",
    "santander", "bci", "scotiabank", "itaú", "itau",
    "transbank", "sii", "cmf", "sernac", "falabella", "ripley",
    "previred", "afp", "isapre",
  ];
  const lower = content.toLowerCase();
  return patterns.filter((p) => lower.includes(p));
}

function buildUserPrompt(
  input: AnalyzeEmailInput,
  whoisSummary: string,
  cmfSummary: string,
  patternSummary: string
): string {
  const emailPreview = input.emailContent.length > 3000
    ? input.emailContent.slice(0, 3000) + "\n[... contenido truncado ...]"
    : input.emailContent;

  return `Analiza este correo potencialmente fraudulento:

REMITENTE: ${input.senderEmail ?? "(no especificado)"}
ASUNTO: ${input.subject ?? "(no especificado)"}

CONTENIDO DEL CORREO:
${emailPreview}

DATOS EXTERNOS RECOPILADOS:
- WHOIS del dominio remitente: ${whoisSummary}
- Verificación CMF: ${cmfSummary}
- Patrones sospechosos detectados: ${patternSummary}

Genera el informe JSON de riesgo.`;
}

export async function analyzeEmail(input: AnalyzeEmailInput): Promise<FraudReport> {
  const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

  // Decode base64 if needed
  let emailContent = input.emailContent;
  if (/^[A-Za-z0-9+/=\n]+$/.test(emailContent.trim()) && emailContent.length > 100) {
    try {
      emailContent = Buffer.from(emailContent.trim(), "base64").toString("utf-8");
    } catch {
      // Not base64, use as-is
    }
  }

  const resolvedInput: AnalyzeEmailInput = { ...input, emailContent };

  // Run pattern check immediately (synchronous)
  const patterns = checkEmailPatterns(emailContent, input.senderEmail, input.subject);

  // Determine institutions to verify with CMF
  const mentionedInstitutions = extractMentionedInstitutions(emailContent);

  // Resolve domain for WHOIS
  const senderDomain = input.senderEmail ? extractDomainFromEmail(input.senderEmail) : null;

  // Run WHOIS and CMF lookups in parallel
  const [whoisData, cmfResult] = await Promise.all([
    senderDomain ? lookupDomainWhois(senderDomain) : Promise.resolve(null),
    mentionedInstitutions.length > 0
      ? verifyCmfEntity(mentionedInstitutions[0])
      : Promise.resolve(null),
  ]);

  // Build summaries for the prompt
  const whoisSummary = whoisData
    ? `dominio=${whoisData.domain}, registrador=${whoisData.registrar ?? "desconocido"}, ` +
      `creado=${whoisData.created ?? "desconocido"}, país=${whoisData.country ?? "desconocido"}, ` +
      `estado=${whoisData.status ?? "desconocido"}`
    : "No se pudo obtener información WHOIS del dominio";

  const cmfSummary = cmfResult
    ? cmfResult.found
      ? `La institución "${cmfResult.entityName}" SÍ está registrada en CMF (tipo: ${cmfResult.entityType})`
      : `La institución mencionada NO está registrada en CMF Chile`
    : "No se verificó ninguna institución chilena en este correo";

  const patternSummary =
    patterns.suspiciousCount > 0
      ? `${patterns.suspiciousCount} patrones sospechosos: ${patterns.details.join("; ")}`
      : "No se detectaron patrones sospechosos automáticamente";

  const userPrompt = buildUserPrompt(resolvedInput, whoisSummary, cmfSummary, patternSummary);

  const response = await client.messages.create({
    model: "claude-sonnet-4-5",
    max_tokens: 1500,
    system: [
      {
        type: "text",
        text: SYSTEM_PROMPT,
        cache_control: { type: "ephemeral" },
      },
    ],
    messages: [{ role: "user", content: userPrompt }],
  });

  const rawText = response.content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("");

  // Extract JSON from the response (handle markdown code blocks)
  const jsonMatch = rawText.match(/```(?:json)?\s*([\s\S]+?)\s*```/) ?? rawText.match(/(\{[\s\S]+\})/);

  if (!jsonMatch) {
    // Fallback report if Claude doesn't return valid JSON
    return {
      riskScore: 50,
      riskLevel: "MEDIUM",
      indicators: patterns.patterns,
      explanation: rawText.slice(0, 500),
      recommendations: ["Verificar manualmente con la institución usando canales oficiales"],
    };
  }

  try {
    const parsed = JSON.parse(jsonMatch[1]) as Partial<FraudReport>;
    return {
      riskScore: Number(parsed.riskScore) || 50,
      riskLevel: parsed.riskLevel ?? "MEDIUM",
      indicators: Array.isArray(parsed.indicators) ? parsed.indicators : patterns.patterns,
      domainAge: whoisData?.created,
      domainCountry: whoisData?.country,
      cmfRegistered: cmfResult?.found,
      explanation: parsed.explanation ?? "Análisis no disponible",
      recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : [],
    };
  } catch {
    return {
      riskScore: 50,
      riskLevel: "MEDIUM",
      indicators: patterns.patterns,
      explanation: "Error al parsear el informe. " + rawText.slice(0, 300),
      recommendations: ["Verificar manualmente con la institución usando canales oficiales"],
    };
  }
}
