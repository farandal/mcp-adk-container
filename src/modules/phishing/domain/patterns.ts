import type { PatternCheckResult } from "../../../core/types.js";

const SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".work", ".click", ".link", ".site", ".online", ".tech", ".info"];

const URGENCY_KEYWORDS = [
  "urgente", "urgente!", "inmediato", "expira hoy", "vence hoy", "última oportunidad",
  "cuenta suspendida", "cuenta bloqueada", "verificar ahora", "actuar ahora",
  "su cuenta será cerrada", "acceso denegado", "alerta de seguridad",
  "urgent", "immediate action", "account suspended", "verify now", "act now",
];

const CHILEAN_IMPERSONATION_PATTERNS = [
  { pattern: /sii\.cl/i, institution: "SII (Servicio de Impuestos Internos)" },
  { pattern: /cmfchile\.cl/i, institution: "CMF (Comisión para el Mercado Financiero)" },
  { pattern: /sernac\.cl/i, institution: "SERNAC" },
  { pattern: /bancochile/i, institution: "Banco de Chile" },
  { pattern: /santander/i, institution: "Santander Chile" },
  { pattern: /bci\.cl/i, institution: "BCI" },
  { pattern: /scotiabank/i, institution: "Scotiabank Chile" },
  { pattern: /itau/i, institution: "Itaú Chile" },
  { pattern: /banco.estado/i, institution: "BancoEstado" },
  { pattern: /falabella/i, institution: "Falabella" },
  { pattern: /ripley/i, institution: "Ripley" },
  { pattern: /transbank/i, institution: "Transbank" },
  { pattern: /previred/i, institution: "PreviRed" },
  { pattern: /afp/i, institution: "AFP" },
  { pattern: /isapre/i, institution: "Isapre" },
];

const SUSPICIOUS_URL_PATTERNS = [
  /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  /bit\.ly|tinyurl|t\.co|ow\.ly|goo\.gl/i,
  /[a-z0-9-]{30,}\.(com|net|org|cl)/i,
];

const UNICODE_LOOKALIKE_PATTERN = /[^\x00-\x7F\xC0-\xFF]/;

function extractDomain(email: string): string | null {
  const match = email.match(/@([^>@\s]+)/);
  return match ? match[1].toLowerCase() : null;
}

function extractDisplayName(email: string): string | null {
  const match = email.match(/^([^<]+)</);
  return match ? match[1].trim().toLowerCase() : null;
}

function extractLinksFromText(text: string): string[] {
  const urlPattern = /https?:\/\/[^\s<>"]+/gi;
  return text.match(urlPattern) ?? [];
}

export function checkEmailPatterns(
  emailContent: string,
  senderEmail?: string,
  subject?: string
): PatternCheckResult {
  const patterns: string[] = [];
  const details: string[] = [];

  const fullText = [emailContent, subject ?? "", senderEmail ?? ""].join(" ").toLowerCase();
  const links = extractLinksFromText(emailContent);

  for (const keyword of URGENCY_KEYWORDS) {
    if (fullText.includes(keyword.toLowerCase())) {
      patterns.push("urgency_language");
      details.push(`Lenguaje de urgencia detectado: "${keyword}"`);
      break;
    }
  }

  if (senderEmail) {
    const domain = extractDomain(senderEmail);
    if (domain) {
      for (const tld of SUSPICIOUS_TLDS) {
        if (domain.endsWith(tld)) {
          patterns.push("suspicious_tld");
          details.push(`Dominio del remitente usa TLD sospechoso: ${tld}`);
          break;
        }
      }

      const displayName = extractDisplayName(senderEmail);
      if (displayName) {
        for (const { pattern, institution } of CHILEAN_IMPERSONATION_PATTERNS) {
          if (pattern.test(displayName) && !pattern.test(domain)) {
            patterns.push("sender_spoofing");
            details.push(`Nombre muestra "${institution}" pero dominio real es "${domain}" — posible suplantación`);
          }
        }
      }

      for (const { pattern, institution } of CHILEAN_IMPERSONATION_PATTERNS) {
        if (pattern.test(fullText) && !pattern.test(domain)) {
          if (!patterns.includes("institution_mismatch")) {
            patterns.push("institution_mismatch");
            details.push(`Se menciona "${institution}" en el correo pero el remitente no usa el dominio oficial`);
          }
        }
      }
    }
  }

  for (const link of links) {
    for (const urlPattern of SUSPICIOUS_URL_PATTERNS) {
      if (urlPattern.test(link)) {
        if (!patterns.includes("suspicious_links")) {
          patterns.push("suspicious_links");
          details.push(`Enlace sospechoso detectado: ${link.slice(0, 80)}...`);
        }
        break;
      }
    }
  }

  if (links.length > 5) {
    patterns.push("excessive_links");
    details.push(`Cantidad inusual de enlaces: ${links.length}`);
  }

  if (UNICODE_LOOKALIKE_PATTERN.test(subject ?? "") || UNICODE_LOOKALIKE_PATTERN.test(senderEmail ?? "")) {
    patterns.push("unicode_lookalike");
    details.push("Caracteres Unicode inusuales detectados en asunto o remitente — posible homografía");
  }

  const credentialKeywords = ["contraseña", "password", "clave", "rut", "número de tarjeta", "cvv", "pin"];
  for (const kw of credentialKeywords) {
    if (fullText.includes(kw)) {
      if (!patterns.includes("credential_request")) {
        patterns.push("credential_request");
        details.push(`Solicita información sensible: "${kw}"`);
      }
    }
  }

  if (senderEmail && !senderEmail.includes("@")) {
    patterns.push("malformed_sender");
    details.push("Dirección de remitente malformada (sin dominio)");
  }

  return { patterns, suspiciousCount: patterns.length, details };
}
