import { useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { iocApi, type VirusTotalLookupResult } from '@/api/client';
import { useAppStore } from '@/store';

export function VirusTotalLookup() {
  const navigate = useNavigate();
  const { domain, addTechniques, replaceTechniques, setOverlayGroup } = useAppStore();
  const [indicator, setIndicator] = useState('');
  const lookup = useMutation({
    mutationFn: () => iocApi.virusTotalLookup({ indicator, domain }),
  });

  const result = lookup.data ?? null;
  const ttpIds = result?.ttps.map(item => item.attack_id) ?? [];

  const showOnMatrix = (ids: string[]) => {
    replaceTechniques(ids);
    navigate('/navigator');
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="VirusTotal IOC Lookup" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
            <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
              <div>
                <h2 className="text-base font-semibold text-white">Check IOC and connect it to ATT&CK context</h2>
                <p className="mt-2 max-w-3xl text-sm text-gray-400">
                  Look up an IP, domain, URL, MD5, SHA1, or SHA256 in VirusTotal. AdversaryGraph shows detection context,
                  extracted ATT&CK IDs, and local actor matches by group name or alias.
                </p>
              </div>
              <a
                href="https://www.virustotal.com/gui/home/search"
                target="_blank"
                rel="noreferrer"
                className="h-fit rounded border border-gray-700 px-3 py-2 text-xs font-semibold text-gray-300 hover:border-gray-500 hover:text-white"
              >
                Open VirusTotal ↗
              </a>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <input
                value={indicator}
                onChange={event => setIndicator(event.target.value)}
                onKeyDown={event => {
                  if (event.key === 'Enter' && indicator.trim()) lookup.mutate();
                }}
                placeholder="IP, domain, URL, MD5, SHA1, or SHA256..."
                className="min-w-[320px] flex-1 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 outline-none focus:border-mitre-accent"
              />
              <button
                type="button"
                disabled={!indicator.trim() || lookup.isPending}
                onClick={() => lookup.mutate()}
                className="rounded bg-mitre-accent px-4 py-2 text-sm font-semibold text-white hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {lookup.isPending ? 'Checking...' : 'Check IOC'}
              </button>
            </div>
            {lookup.error && (
              <div className="mt-3 rounded border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-100">
                {lookup.error instanceof Error ? lookup.error.message : String(lookup.error)}
              </div>
            )}
          </section>

          {result && (
            <>
              <ResultSummary result={result} />

              <section className="grid gap-4 xl:grid-cols-[1fr_420px]">
                <Panel title={`ATT&CK TTPs (${result.ttps.length})`}>
                  {result.ttps.length > 0 ? (
                    <>
                      <div className="mb-3 flex flex-wrap gap-2">
                        <button onClick={() => addTechniques(ttpIds)} className="primary-action">Add to My TTPs</button>
                        <button onClick={() => showOnMatrix(ttpIds)} className="secondary-action">Show on matrix</button>
                      </div>
                      <div className="space-y-2">
                        {result.ttps.map(ttp => (
                          <div key={ttp.attack_id} className="rounded border border-gray-800 bg-gray-950/40 p-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <a href={`/navigator?technique=${ttp.attack_id}`} className="font-mono text-sm text-mitre-accent hover:underline">{ttp.attack_id}</a>
                              <span className="text-sm text-white">{ttp.name || 'Technique from VirusTotal context'}</span>
                            </div>
                            {ttp.tactics.length > 0 && (
                              <div className="mt-2 flex flex-wrap gap-1.5">
                                {ttp.tactics.map(tactic => <span key={tactic} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{tactic}</span>)}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </>
                  ) : (
                    <Empty text="No ATT&CK technique IDs were present in the VirusTotal response for this IOC." />
                  )}
                </Panel>

                <Panel title={`Local actor matches (${result.actors.length})`}>
                  {result.actors.length > 0 ? (
                    <div className="space-y-3">
                      {result.actors.map(actor => (
                        <div key={actor.attack_id} className="rounded border border-gray-800 bg-gray-950/40 p-3">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <a href={`/apt?group=${actor.attack_id}`} className="text-sm font-semibold text-white hover:text-mitre-accent">{actor.name}</a>
                              <div className="mt-1 font-mono text-xs text-mitre-accent">{actor.attack_id}</div>
                            </div>
                            <span className="rounded bg-purple-950/40 px-2 py-1 text-[10px] text-purple-300">
                              {actor.technique_ids.length} TTPs
                            </span>
                          </div>
                          {actor.matched_terms.length > 0 && (
                            <div className="mt-2 text-xs text-gray-500">Matched: {actor.matched_terms.join(', ')}</div>
                          )}
                          {actor.aliases.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {actor.aliases.slice(0, 8).map(alias => <span key={alias} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{alias}</span>)}
                            </div>
                          )}
                          <div className="mt-3 flex flex-wrap gap-2">
                            <button onClick={() => navigate(`/apt?group=${actor.attack_id}`)} className="secondary-action">Actor page</button>
                            <button onClick={() => { setOverlayGroup(actor.attack_id, actor.name); navigate('/navigator'); }} className="secondary-action">Overlay actor</button>
                            <button onClick={() => addTechniques(actor.technique_ids)} className="secondary-action">Add actor TTPs</button>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <Empty text="No local ATT&CK actor profile matched the VirusTotal names, tags, or labels." />
                  )}
                </Panel>
              </section>

              <section className="grid gap-4 xl:grid-cols-2">
                <Panel title={`Detections (${result.detections.length})`}>
                  {result.detections.length > 0 ? (
                    <div className="overflow-hidden rounded border border-gray-800">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-gray-950 text-gray-500">
                          <tr><th className="p-2">Engine</th><th className="p-2">Category</th><th className="p-2">Result</th></tr>
                        </thead>
                        <tbody>
                          {result.detections.map(row => (
                            <tr key={`${row.engine}-${row.result}`} className="border-t border-gray-800">
                              <td className="p-2 text-gray-300">{row.engine}</td>
                              <td className={row.category === 'malicious' ? 'p-2 text-red-300' : 'p-2 text-amber-300'}>{row.category || '-'}</td>
                              <td className="p-2 text-gray-400">{row.result || '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : <Empty text="No malicious or named engine detections were returned." />}
                </Panel>

                <Panel title="Labels and context">
                  <LabelBlock title="Threat names" values={result.threat_names} />
                  <LabelBlock title="Tags" values={result.tags} />
                  <div className="mt-3 grid grid-cols-3 gap-2">
                    <Metric label="YARA" value={Number(result.context.crowdsourced_yara_count ?? 0)} />
                    <Metric label="IDS" value={Number(result.context.crowdsourced_ids_count ?? 0)} />
                    <Metric label="Sigma" value={Number(result.context.sigma_result_count ?? 0)} />
                  </div>
                </Panel>
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function ResultSummary({ result }: { result: VirusTotalLookupResult }) {
  const stats = result.last_analysis_stats ?? {};
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const tone = malicious > 0 ? 'border-red-500/50 bg-red-950/25' : suspicious > 0 ? 'border-amber-500/50 bg-amber-950/25' : 'border-emerald-500/50 bg-emerald-950/20';
  return (
    <section className={`rounded-lg border p-4 ${tone}`}>
      <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded bg-gray-950/60 px-2 py-1 font-mono text-xs text-gray-300">{result.type}</span>
            <h2 className="break-all text-base font-semibold text-white">{result.indicator}</h2>
          </div>
          <p className="mt-2 text-sm text-gray-300">{result.summary}</p>
          <div className="mt-3 flex flex-wrap gap-2 text-xs">
            <a href={result.virustotal_url} target="_blank" rel="noreferrer" className="rounded border border-gray-700 px-2 py-1 text-gray-300 hover:border-gray-500 hover:text-white">VirusTotal report ↗</a>
            {result.permalink && result.permalink !== result.virustotal_url && (
              <a href={result.permalink} target="_blank" rel="noreferrer" className="rounded border border-gray-700 px-2 py-1 text-gray-300 hover:border-gray-500 hover:text-white">Permalink ↗</a>
            )}
          </div>
        </div>
        <div className="grid grid-cols-4 gap-2 lg:min-w-[420px]">
          <Metric label="Malicious" value={malicious} danger />
          <Metric label="Suspicious" value={suspicious} warning />
          <Metric label="Harmless" value={stats.harmless ?? 0} />
          <Metric label="Undetected" value={stats.undetected ?? 0} />
        </div>
      </div>
    </section>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4"><h2 className="mb-3 text-base font-semibold text-white">{title}</h2>{children}</section>;
}

function Metric({ label, value, danger, warning }: { label: string; value: number; danger?: boolean; warning?: boolean }) {
  const color = danger ? 'text-red-300' : warning ? 'text-amber-300' : 'text-white';
  return <div className="rounded border border-gray-800 bg-gray-950/50 p-3"><b className={`block text-lg ${color}`}>{value}</b><span className="text-[10px] text-gray-500">{label}</span></div>;
}

function LabelBlock({ title, values }: { title: string; values: string[] }) {
  return (
    <div className="mb-3">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">{title}</h3>
      {values.length ? (
        <div className="flex flex-wrap gap-1.5">
          {values.slice(0, 32).map(value => <span key={value} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{value}</span>)}
        </div>
      ) : <div className="text-xs text-gray-600">None returned.</div>}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div className="rounded border border-gray-800 bg-gray-950/40 p-4 text-sm text-gray-500">{text}</div>;
}
