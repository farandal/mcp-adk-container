import type { CmfEntityResult } from "../../../core/types.js";

interface CmfInstitution {
  Codigo?: string;
  Nombre?: string;
  Tipo?: string;
  [key: string]: unknown;
}

interface CmfApiResponse {
  Instituciones?: {
    Institucion?: CmfInstitution | CmfInstitution[];
  };
}

function normalizeText(text: string): string {
  return text
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9\s]/g, " ")
    .trim();
}

function computeMatchScore(query: string, candidate: string): number {
  const normalQuery = normalizeText(query);
  const normalCandidate = normalizeText(candidate);

  if (normalCandidate === normalQuery) return 1.0;
  if (normalCandidate.includes(normalQuery)) return 0.9;
  if (normalQuery.includes(normalCandidate)) return 0.8;

  const queryWords = normalQuery.split(/\s+/).filter((w) => w.length > 2);
  const candidateWords = new Set(normalCandidate.split(/\s+/));
  const matchedWords = queryWords.filter((w) => candidateWords.has(w));

  return queryWords.length > 0 ? matchedWords.length / queryWords.length : 0;
}

export async function verifyCmfEntity(institutionName: string): Promise<CmfEntityResult> {
  const apiKey = process.env.CMF_API_KEY;

  if (!apiKey) {
    return { found: false, matchScore: 0 };
  }

  try {
    const url = `https://api.cmfchile.cl/api-sbifv3/recursos_api/instituciones?apikey=${apiKey}&formato=json`;
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return { found: false };
    }

    const data = (await response.json()) as CmfApiResponse;
    const rawList = data?.Instituciones?.Institucion;
    if (!rawList) return { found: false };

    const institutions: CmfInstitution[] = Array.isArray(rawList) ? rawList : [rawList];

    let bestMatch: CmfEntityResult = { found: false, matchScore: 0 };

    for (const inst of institutions) {
      const name = inst.Nombre ?? "";
      const score = computeMatchScore(institutionName, name);
      if (score > (bestMatch.matchScore ?? 0) && score >= 0.5) {
        bestMatch = {
          found: true,
          entityName: name,
          entityType: inst.Tipo ?? "Institución Financiera",
          matchScore: score,
        };
      }
    }

    return bestMatch;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error("[cmf] Error:", message);
    return { found: false };
  }
}
