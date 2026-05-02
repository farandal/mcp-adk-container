import type { WhoisData } from "../../../core/types.js";

interface RdapResponse {
  ldhName?: string;
  unicodeName?: string;
  entities?: RdapEntity[];
  events?: RdapEvent[];
  nameservers?: Array<{ ldhName: string }>;
  status?: string[];
  links?: Array<{ href: string }>;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: unknown[];
  publicIds?: Array<{ type: string; identifier: string }>;
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

function extractRegistrarFromEntities(entities: RdapEntity[]): string | undefined {
  const registrar = entities.find((e) => e.roles?.includes("registrar"));
  if (!registrar?.vcardArray) return undefined;
  const vcard = registrar.vcardArray as unknown[][];
  if (!Array.isArray(vcard[1])) return undefined;
  const fnEntry = (vcard[1] as unknown[][]).find((entry) => Array.isArray(entry) && entry[0] === "fn");
  return fnEntry ? String(fnEntry[3]) : undefined;
}

function extractCountryFromEntities(entities: RdapEntity[]): string | undefined {
  for (const entity of entities) {
    if (!entity.vcardArray) continue;
    const vcard = entity.vcardArray as unknown[][];
    if (!Array.isArray(vcard[1])) continue;
    const adrEntry = (vcard[1] as unknown[][]).find((e) => Array.isArray(e) && e[0] === "adr");
    if (adrEntry && Array.isArray(adrEntry[3])) {
      const adrParts = adrEntry[3] as string[];
      const country = adrParts[6];
      if (country) return country;
    }
  }
  return undefined;
}

export async function lookupDomainWhois(domain: string): Promise<WhoisData> {
  const cleanDomain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();

  try {
    const response = await fetch(`https://rdap.org/domain/${cleanDomain}`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return { domain: cleanDomain, raw: { error: `RDAP returned ${response.status}` } };
    }

    const data = (await response.json()) as RdapResponse;

    const created = data.events?.find((e) => e.eventAction === "registration")?.eventDate;
    const expires = data.events?.find((e) => e.eventAction === "expiration")?.eventDate;

    const registrar = data.entities ? extractRegistrarFromEntities(data.entities) : undefined;
    const country = data.entities ? extractCountryFromEntities(data.entities) : undefined;

    return {
      domain: cleanDomain,
      registrar,
      created: created ? new Date(created).toISOString().split("T")[0] : undefined,
      expires: expires ? new Date(expires).toISOString().split("T")[0] : undefined,
      country,
      status: data.status?.join(", "),
      nameservers: data.nameservers?.map((ns) => ns.ldhName),
      raw: data,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { domain: cleanDomain, raw: { error: message } };
  }
}
