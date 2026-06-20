import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { iocApi } from '@/api/client';
import { useAppStore } from '@/store';

const OBSERVABLE_TYPES = new Set(['ioc', 'ip', 'domain', 'url', 'hash']);

export function IOCNodeDetail() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { addTechniques, replaceTechniques } = useAppStore();
  const value = params.get('value') ?? '';
  const type = params.get('type') ?? 'unknown';
  const tier = params.get('tier') ?? '';
  const sources = useMemo(() => (params.get('sources') ?? '').split(',').map(item => item.trim()).filter(Boolean), [params]);
  const isObservable = OBSERVABLE_TYPES.has(type);
  const isTechnique = /^T\d{4}(?:\.\d{3})?$/i.test(value);
  const isActorId = /^G\d{4}$/i.test(value);
  const canSearchIocs = Boolean(value.trim()) && (isObservable || ['malware', 'tag', 'report', 'name', 'classification', 'reputation'].includes(type));
  const library = useQuery({
    queryKey: ['ioc-node-library', type, value],
    queryFn: () => iocApi.library({ search: value, limit: 10 }),
    enabled: canSearchIocs,
  });
  const matchedTechniqueIds = useMemo(() => {
    const fromItems = library.data?.items.flatMap(item => item.technique_ids ?? []) ?? [];
    return Array.from(new Set([...(isTechnique ? [value.toUpperCase()] : []), ...fromItems])).sort();
  }, [isTechnique, library.data?.items, value]);

  const showOnMatrix = () => {
    replaceTechniques(matchedTechniqueIds);
    navigate('/navigator');
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="Investigation Node Detail" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-gray-800 px-2 py-1 font-mono text-[10px] text-gray-300">{type}</span>
                  {tier && <span className="rounded bg-gray-800 px-2 py-1 text-[10px] text-gray-400">Tier {tier}</span>}
                  {sources.map(source => <span key={source} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-400">{source}</span>)}
                </div>
                <h2 className="mt-3 break-all font-mono text-xl font-semibold text-white">{value || 'Unknown node'}</h2>
                <p className="mt-3 max-w-4xl text-sm leading-relaxed text-gray-400">{nodeSummary(type, value)}</p>
              </div>
              <div className="grid min-w-[260px] gap-2 text-xs">
                {isObservable && <button onClick={() => navigate(`/ioc-investigation?indicator=${encodeURIComponent(value)}`)} className="primary-action">Investigate IOC</button>}
                {canSearchIocs && <button onClick={() => navigate(`/ioc-library?search=${encodeURIComponent(value)}`)} className="secondary-action">Search IOC Library</button>}
                {isObservable && <button onClick={() => navigate(`/virustotal?indicator=${encodeURIComponent(value)}`)} className="secondary-action">VirusTotal Lookup</button>}
                {isTechnique && <button onClick={() => navigate(`/navigator?technique=${value.toUpperCase()}`)} className="secondary-action">Open Technique</button>}
                {isActorId && <button onClick={() => navigate(`/apt?group=${value.toUpperCase()}`)} className="secondary-action">Open Actor</button>}
                {type === 'actor' && !isActorId && <button onClick={() => navigate(`/apt?search=${encodeURIComponent(value)}`)} className="secondary-action">Search Actor Library</button>}
              </div>
            </div>
          </section>

          <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
            <Panel title="Investigation Questions">
              <Question title="Malicious?" answer={maliciousAnswer(type)} refText={sourceRef(sources)}>
                {maliciousWhy(type, value)}
              </Question>
              <Question title="TTP?" answer={matchedTechniqueIds.length ? 'possible / mapped' : isTechnique ? 'direct technique' : 'no direct mapping'} refText={matchedTechniqueIds.join(', ') || sourceRef(sources)}>
                {matchedTechniqueIds.length
                  ? 'This node has direct or IOC-library ATT&CK technique context. Validate the behavior evidence before using it in a client report.'
                  : 'This node does not currently carry a direct ATT&CK mapping. Use it as pivot or context unless a source provides behavior evidence.'}
              </Question>
              <Question title="Actor?" answer={type === 'actor' || isActorId ? 'actor lead' : 'not direct actor evidence'} refText={sourceRef(sources)}>
                {type === 'actor' || isActorId
                  ? 'This node points to an actor name or ATT&CK group ID. Treat it as a lead requiring source validation, not attribution.'
                  : 'This node is not an actor. Actor relevance requires a source-backed actor link, alias match, or report context.'}
              </Question>
            </Panel>

            <Panel title="Actions">
              <div className="space-y-2">
                <button disabled={!matchedTechniqueIds.length} onClick={() => addTechniques(matchedTechniqueIds)} className="primary-action w-full disabled:opacity-40">Add mapped TTPs</button>
                <button disabled={!matchedTechniqueIds.length} onClick={showOnMatrix} className="secondary-action w-full disabled:opacity-40">Show mapped TTPs on Matrix</button>
                <button onClick={() => navigator.clipboard.writeText(value)} className="secondary-action w-full">Copy node value</button>
              </div>
            </Panel>
          </section>

          {canSearchIocs && (
            <Panel title={`Matching IOC Library Records (${library.data?.total ?? 0})`}>
              {library.isLoading && <Empty text="Searching local IOC library..." />}
              {library.error && <ErrorBox error={library.error} />}
              {!library.isLoading && !library.error && !library.data?.items.length && <Empty text="No local IOC records match this node yet." />}
              <div className="space-y-2">
                {library.data?.items.map(item => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => navigate(`/ioc-library/${item.id}`)}
                    className="w-full rounded border border-gray-800 bg-gray-950/50 p-3 text-left hover:border-mitre-accent/60"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] text-gray-300">{item.type}</span>
                      <span className="break-all font-mono text-sm text-white">{item.value}</span>
                    </div>
                    <div className="mt-1 text-[11px] text-gray-500">{item.source} · confidence {item.confidence} · last seen {item.last_seen || '-'}</div>
                    {item.description && <p className="mt-2 line-clamp-2 text-xs text-gray-400">{item.description}</p>}
                    {item.technique_ids.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {item.technique_ids.slice(0, 12).map(id => <span key={id} className="rounded bg-mitre-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-mitre-accent">{id}</span>)}
                      </div>
                    )}
                  </button>
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

function nodeSummary(type: string, value: string) {
  if (!value) return 'This page was opened without a node value.';
  if (OBSERVABLE_TYPES.has(type)) return 'Observable node. Use this page to pivot into IOC Library records, enrichment, VirusTotal lookup, and a deeper IOC investigation.';
  if (type === 'actor') return 'Actor lead node. It can help pivot into ATT&CK group context, but it should not be treated as attribution without source-backed evidence.';
  if (type === 'suspicious-pattern') return 'Behavior pattern node from investigation enrichment. Use it as a clue for TTP mapping and maliciousness assessment.';
  if (type === 'tag' || type === 'classification' || type === 'reputation') return 'Context node from an enrichment source. It can support triage but usually needs another source before a firm conclusion.';
  return 'Relationship graph node. Use the source context and matching IOC records to decide whether this is an actionable pivot.';
}

function maliciousAnswer(type: string) {
  if (['malware', 'suspicious-pattern', 'reputation', 'vulnerability'].includes(type)) return 'suspicious lead';
  if (OBSERVABLE_TYPES.has(type)) return 'needs enrichment';
  return 'context';
}

function maliciousWhy(type: string, value: string) {
  if (['malware', 'suspicious-pattern', 'reputation', 'vulnerability'].includes(type)) {
    return `${value} has security-relevant context by node type. Validate the original source before marking it malicious.`;
  }
  if (OBSERVABLE_TYPES.has(type)) {
    return `${value} is an observable. It becomes malicious only when enrichment, reports, sandbox behavior, or source reputation supports that conclusion.`;
  }
  return `${value || 'This node'} is context for pivoting. It is not enough by itself to assess maliciousness.`;
}

function sourceRef(sources: string[]) {
  return sources.length ? sources.join(', ') : 'No source metadata was provided in the node URL.';
}

function Question({ title, answer, refText, children }: { title: string; answer: string; refText: string; children: ReactNode }) {
  return (
    <div className="mb-3 rounded border border-gray-800 bg-gray-950/50 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-gray-200">{title}</span>
        <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">{answer}</span>
      </div>
      <p className="mt-2 text-sm leading-6 text-gray-400">{children}</p>
      <div className="mt-2 break-all text-[10px] text-gray-600">Ref. {refText}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</div>
      <div className="p-4">{children}</div>
    </section>
  );
}

function Empty({ text }: { text: string }) {
  return <p className="text-sm text-gray-600">{text}</p>;
}

function ErrorBox({ error }: { error: unknown }) {
  return (
    <div className="rounded border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-100">
      {error instanceof Error ? error.message : String(error)}
    </div>
  );
}
