const configuredBaseUrl =
  (import.meta as ImportMeta & { env?: Record<string, string> }).env?.VITE_REFERENCE_URL ||
  'https://1200km.com/anomaly-detection-atlas';

export const REFERENCE_BASE_URL = configuredBaseUrl.replace(/\/$/, '');

// ── Ecosystem links ───────────────────────────────────────────────────────────

const IDENTITY_TECHNIQUES = new Set([
  'T1078','T1098','T1110','T1111','T1136','T1531','T1539',
  'T1550','T1552','T1555','T1556','T1558','T1606','T1621',
]);

export interface EcosystemLink { label: string; url: string }

export function getEcosystemLinks(attackId: string): EcosystemLink[] {
  const base = attackId.split('.')[0];
  const links: EcosystemLink[] = [
    { label: 'CTI Analyst Field Manual',  url: 'https://1200km.com/cti-analyst-field-manual/' },
    { label: 'ThreatMapper Web Tool',     url: 'https://1200km.com/threat-matrix/' },
  ];
  if (IDENTITY_TECHNIQUES.has(base))
    links.splice(1, 0, { label: 'Insider Threat Detection Guide', url: 'https://1200km.com/insider-threat-detection/' });
  return links;
}

export interface TechniqueReference {
  label: string;
  path: string;
  anchor: string;
  context: string;
}

export type TechniqueReferenceIndex = Record<string, TechniqueReference[]>;

export async function loadTechniqueReferenceIndex(): Promise<TechniqueReferenceIndex> {
  const response = await fetch(`${REFERENCE_BASE_URL}/ttp-reference-index.json`);
  if (!response.ok) throw new Error('Unable to load the TTP reference index');
  return response.json();
}

export function techniqueReferenceUrl(reference: TechniqueReference): string {
  return `${REFERENCE_BASE_URL}/${reference.path}/#${reference.anchor}`;
}
