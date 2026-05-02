export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface FraudReport {
  riskScore: number;
  riskLevel: RiskLevel;
  indicators: string[];
  domainAge?: string;
  domainCountry?: string;
  cmfRegistered?: boolean;
  explanation: string;
  recommendations: string[];
}

export interface WhoisData {
  domain: string;
  registrar?: string;
  created?: string;
  expires?: string;
  country?: string;
  status?: string;
  nameservers?: string[];
  raw?: unknown;
}

export interface CmfEntityResult {
  found: boolean;
  entityName?: string;
  entityType?: string;
  matchScore?: number;
}

export interface PatternCheckResult {
  patterns: string[];
  suspiciousCount: number;
  details: string[];
}

export interface AnalyzeEmailInput {
  emailContent: string;
  senderEmail?: string;
  subject?: string;
}
