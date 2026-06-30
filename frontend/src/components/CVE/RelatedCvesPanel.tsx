import { Link } from 'react-router-dom';
import type { CVECorrelation } from '@/api/client';

type Props = {
  title?: string;
  items: CVECorrelation[] | undefined;
  loading?: boolean;
  empty?: string;
  limit?: number;
};

export function RelatedCvesPanel({
  title = 'Related CVEs',
  items,
  loading = false,
  empty = 'No evidence-backed CVE correlation is stored yet.',
  limit = 8,
}: Props) {
  const rows = (items ?? []).slice(0, limit);
  return (
    <section className="rounded border border-gray-800 bg-gray-950/40">
      <div className="flex items-center justify-between gap-3 border-b border-gray-800 px-3 py-2">
        <h3 className="text-xs font-semibold uppercase text-gray-400">{title}</h3>
        <span className="text-[10px] text-gray-600">{items?.length ?? 0} links</span>
      </div>
      <div className="space-y-2 p-3">
        {loading && <p className="text-xs text-gray-500">Loading CVE correlations...</p>}
        {!loading && rows.length === 0 && <p className="text-xs text-gray-600">{empty}</p>}
        {rows.map(item => (
          <Link
            key={`${item.cve.cve_id}-${item.relationship}-${item.source}-${item.path.map(part => String(part.id ?? part.value ?? '')).join(':')}`}
            to={`/cve?search=${encodeURIComponent(item.cve.cve_id)}`}
            className="block rounded border border-gray-800 bg-gray-900/60 p-2 hover:border-mitre-accent/70"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-xs font-semibold text-mitre-accent">{item.cve.cve_id}</span>
              <span className={`rounded px-2 py-0.5 text-[10px] font-semibold ${severityClass(item.cve.cvss.severity)}`}>
                {item.cve.cvss.score ? `${item.cve.cvss.severity || 'SCORED'} ${item.cve.cvss.score}` : 'NO NVD SCORE'}
              </span>
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-1 text-[10px] text-gray-500">
              {item.cve.known_exploited && <span className="rounded bg-red-900/50 px-1.5 py-0.5 text-red-200">KEV</span>}
              <span>{item.relationship}</span>
              <span>confidence {item.confidence}</span>
              <span>{item.source}</span>
            </div>
            {item.evidence && <p className="mt-1 line-clamp-3 text-[11px] leading-relaxed text-gray-400">{item.evidence}</p>}
            {item.path.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {item.path.map((part, index) => (
                  <span key={`${index}-${String(part.id ?? part.value ?? part.type)}`} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">
                    {String(part.type ?? 'node')}:{String(part.id ?? part.value ?? '')}
                  </span>
                ))}
              </div>
            )}
          </Link>
        ))}
        {(items?.length ?? 0) > rows.length && (
          <Link to="/cve" className="text-xs text-mitre-accent hover:underline">Open CVE Library for full review</Link>
        )}
      </div>
    </section>
  );
}

function severityClass(severity: string) {
  if (severity === 'CRITICAL') return 'bg-red-900/60 text-red-100';
  if (severity === 'HIGH') return 'bg-orange-900/60 text-orange-100';
  if (severity === 'MEDIUM') return 'bg-amber-900/50 text-amber-100';
  return 'bg-gray-800 text-gray-300';
}
