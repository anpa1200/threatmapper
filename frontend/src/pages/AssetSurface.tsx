import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useDropzone } from 'react-dropzone';
import { useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { assetSurfaceApi, layersApi } from '@/api/client';
import type { AssetSurfaceAnalysisResult, AssetSurfaceAsset } from '@/api/client';
import { IocLink, TtpLink } from '@/utils/ctiLinks';
import { useAppStore } from '@/store';

type Provider = 'claude' | 'openai' | 'gemini' | 'minimax' | 'local';
type AssetSurfaceHistoryItem = AssetSurfaceAnalysisResult & {
  history_id: string;
  created_at: string;
  name: string;
  ttp_count: number;
  high_or_critical_count: number;
};

const ASSET_SURFACE_HISTORY_KEY = 'adversarygraph-asset-surface-history-v1';
const ASSET_SURFACE_HISTORY_LIMIT = 20;

const PROVIDERS: { id: Provider; label: string; model: string }[] = [
  { id: 'local', label: 'Local', model: 'qwen3:8b' },
  { id: 'claude', label: 'Claude', model: 'claude-opus-4-8' },
  { id: 'openai', label: 'OpenAI', model: 'gpt-4.1' },
  { id: 'gemini', label: 'Gemini', model: 'gemini-2.0-flash' },
  { id: 'minimax', label: 'MiniMax', model: 'MiniMax-M3' },
];

const SAMPLE = `name,type,environment,owner,ip,domain,ports,technologies,exposure,criticality,tags
customer-portal,web-app,prod,Digital,203.0.113.10,portal.example.com,"80,443,8443","nginx,nodejs,postgres",internet,critical,"customer-data,pci"
vpn-gateway,remote-access,prod,IT,198.51.100.20,vpn.example.com,"443,500,4500","vpn,sso,mfa",internet,high,"remote-access"
ad-dc-01,identity,prod,IT,10.10.1.10,ad01.corp.local,"53,88,135,389,445","active-directory,windows",internal,critical,"identity"
postgres-payments,database,prod,Payments,10.20.5.15,,"5432","postgresql",internal,critical,"database,payments"`;

export function AssetSurface() {
  const navigate = useNavigate();
  const { domain, addComparisonLayer, clearComparisonLayers, clearTechniques } = useAppStore();
  const [provider, setProvider] = useState<Provider>('local');
  const [useAi, setUseAi] = useState(true);
  const [inventoryName, setInventoryName] = useState('External asset inventory');
  const [text, setText] = useState(SAMPLE);
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<AssetSurfaceAnalysisResult | null>(null);
  const [history, setHistory] = useState<AssetSurfaceHistoryItem[]>(loadAssetSurfaceHistory);
  const [activeHistoryId, setActiveHistoryId] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState('all');
  const [exposureFilter, setExposureFilter] = useState('all');

  const mutation = useMutation({
    mutationFn: (form: FormData) => assetSurfaceApi.analyze(form),
    onSuccess: nextResult => {
      const item = createAssetSurfaceHistoryItem(nextResult, inventoryName);
      setResult(item);
      setActiveHistoryId(item.history_id);
      setHistory(current => {
        const next = [item, ...current.filter(entry => entry.history_id !== item.history_id)].slice(0, ASSET_SURFACE_HISTORY_LIMIT);
        saveAssetSurfaceHistory(next);
        return next;
      });
    },
  });
  const saveLayer = useMutation({
    mutationFn: (ids: string[]) => layersApi.save(`${inventoryName || 'Asset surface'} TTP layer`, ids, domain),
  });

  const onDrop = ([nextFile]: File[]) => {
    if (!nextFile) return;
    setFile(nextFile);
    setText('');
    setInventoryName(nextFile.name.replace(/\.[^.]+$/, ''));
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxFiles: 1,
    accept: {
      'text/csv': ['.csv'],
      'application/json': ['.json'],
      'text/plain': ['.txt', '.tsv', '.log'],
    },
  });

  const filteredAssets = useMemo(() => {
    return (result?.assets ?? []).filter(asset => {
      const riskOk = riskFilter === 'all' || asset.risk_level === riskFilter || asset.ai_risk_level === riskFilter;
      const exposureOk = exposureFilter === 'all' || asset.exposure === exposureFilter;
      return riskOk && exposureOk;
    });
  }, [result?.assets, riskFilter, exposureFilter]);

  const allTtpIds = useMemo(() => {
    return Array.from(new Set((result?.assets ?? []).flatMap(asset => asset.ttp_candidates.map(ttp => ttp.attack_id.toUpperCase())))).sort();
  }, [result?.assets]);

  const run = () => {
    const form = new FormData();
    form.append('provider', provider);
    form.append('use_ai', String(useAi));
    form.append('inventory_name', inventoryName);
    if (file) form.append('file', file);
    else form.append('text', text);
    mutation.mutate(form);
  };

  const canRun = !mutation.isPending && (Boolean(file) || text.trim().length > 0);
  const addWhiteAssetLayer = (replace = false) => {
    if (!allTtpIds.length) return;
    if (replace) {
      clearTechniques();
      clearComparisonLayers();
    }
    addComparisonLayer({
      name: `${inventoryName || 'Asset inventory'} TTPs`,
      techniqueIds: allTtpIds,
      source: 'asset-surface',
      color: '#ffffff',
    });
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="Asset Attack Surface" />
      <div className="grid min-h-0 flex-1 grid-cols-1 overflow-y-auto xl:grid-cols-[400px_minmax(0,1fr)] xl:overflow-hidden">
        <aside className="flex min-h-0 flex-col overflow-y-auto border-r border-gray-700">
          <section className="border-b border-gray-800 p-4">
            <label className="label">Inventory Name</label>
            <input className="field" value={inventoryName} onChange={event => setInventoryName(event.target.value)} />
          </section>

          <section className="border-b border-gray-800 p-4">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">AI Provider</div>
            <div className="grid grid-cols-1 gap-1.5">
              {PROVIDERS.map(item => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setProvider(item.id)}
                  className={`flex items-center justify-between rounded border px-3 py-2 text-xs ${
                    provider === item.id ? 'border-mitre-accent bg-mitre-accent/20 text-white' : 'border-gray-700 text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <span>{item.label}</span>
                  <span className="font-mono text-[10px] opacity-70">{item.model}</span>
                </button>
              ))}
            </div>
            <label className="mt-3 flex items-start gap-2 rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
              <input type="checkbox" checked={useAi} onChange={event => setUseAi(event.target.checked)} />
              <span>Use AI enrichment for attack paths, control gaps, assumptions, and validation gaps. Baseline scoring still runs without AI.</span>
            </label>
          </section>

          <section className="flex min-h-0 flex-1 flex-col p-4">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">Inventory Input</div>
            <textarea
              value={text}
              onChange={event => {
                setText(event.target.value);
                setFile(null);
              }}
              className="min-h-[220px] flex-1 resize-none rounded border border-gray-700 bg-gray-900 px-3 py-2 font-mono text-xs text-gray-200 outline-none focus:border-mitre-accent"
              placeholder="Paste CSV, JSON, hostname/IP list, CMDB export, cloud inventory, or scanner output"
            />
            <div
              {...getRootProps()}
              className={`mt-3 cursor-pointer rounded border-2 border-dashed p-4 text-center text-xs transition-colors ${
                isDragActive ? 'border-mitre-accent bg-mitre-accent/10' : 'border-gray-700 text-gray-600 hover:border-gray-500'
              }`}
            >
              <input {...getInputProps()} />
              {file ? (
                <span className="text-gray-300">{file.name}</span>
              ) : (
                <span>Drop CSV / JSON / TXT inventory or click</span>
              )}
            </div>
            <button type="button" disabled={!canRun} onClick={run} className="primary mt-4 disabled:opacity-50">
              {mutation.isPending ? 'Building matrix...' : 'Analyze Attack Surface'}
            </button>
            {mutation.error && (
              <div className="mt-3 rounded border border-red-900 bg-red-950/30 p-3 text-xs text-red-300">
                {String(mutation.error)}
              </div>
            )}
          </section>

          <section className="min-h-0 border-t border-gray-800 p-4">
            <div className="mb-2 flex items-center justify-between gap-2">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Previous Analyses</div>
              <span className="text-[10px] text-gray-600">{history.length}</span>
            </div>
            <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
              {history.map(item => (
                <div
                  key={item.history_id}
                  role="button"
                  tabIndex={0}
                  onClick={() => {
                    setResult(item);
                    setActiveHistoryId(item.history_id);
                    setInventoryName(item.inventory_name || item.name);
                    setFile(null);
                    setText('');
                  }}
                  onKeyDown={event => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      setResult(item);
                      setActiveHistoryId(item.history_id);
                      setInventoryName(item.inventory_name || item.name);
                      setFile(null);
                      setText('');
                    }
                  }}
                  className={`w-full rounded border p-2 text-left text-xs ${
                    activeHistoryId === item.history_id
                      ? 'border-mitre-accent bg-mitre-accent/10'
                      : 'border-gray-800 bg-gray-950 hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <b className="block truncate text-gray-200">{item.name}</b>
                      <span className="mt-1 block text-[10px] text-gray-600">{new Date(item.created_at).toLocaleString()}</span>
                    </div>
                    <button
                      type="button"
                      onClick={event => {
                        event.stopPropagation();
                        setHistory(current => {
                          const next = current.filter(entry => entry.history_id !== item.history_id);
                          saveAssetSurfaceHistory(next);
                          return next;
                        });
                        if (activeHistoryId === item.history_id) {
                          setResult(null);
                          setActiveHistoryId(null);
                        }
                      }}
                      className="text-[10px] text-gray-600 hover:text-red-300"
                    >
                      delete
                    </button>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1 text-[10px]">
                    <Chip>{item.asset_count} assets</Chip>
                    <Chip>{item.ttp_count} TTPs</Chip>
                    <Chip>{item.high_or_critical_count} high/critical</Chip>
                  </div>
                </div>
              ))}
              {!history.length && (
                <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-600">
                  Completed asset analyses will be saved here on this browser.
                </div>
              )}
            </div>
          </section>
        </aside>

        <main className="min-h-0 overflow-y-auto p-4 lg:p-6">
          {!result ? (
            <EmptyState />
          ) : (
            <div className="mx-auto max-w-7xl space-y-5">
              <section className="flex flex-wrap items-center justify-between gap-3 rounded border border-gray-800 bg-gray-950 p-4">
                <div>
                  <div className="text-sm font-semibold text-white">Attack Surface TTP Layer</div>
                  <p className="mt-1 text-xs text-gray-500">{allTtpIds.length} unique ATT&amp;CK candidates mapped from inventory exposure and AI context.</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button type="button" disabled={!allTtpIds.length} onClick={() => addWhiteAssetLayer(false)} className="secondary-action disabled:opacity-40">Add White Layer</button>
                  <button type="button" disabled={!allTtpIds.length} onClick={() => { addWhiteAssetLayer(true); navigate('/navigator'); }} className="primary-action disabled:opacity-40">Open Matrix</button>
                  <button type="button" disabled={!allTtpIds.length || saveLayer.isPending} onClick={() => saveLayer.mutate(allTtpIds)} className="secondary-action disabled:opacity-40">
                    {saveLayer.isPending ? 'Saving...' : 'Save Layer'}
                  </button>
                  <button type="button" onClick={() => downloadJson(result, `${slug(inventoryName || 'asset-surface')}-matrix.json`)} className="secondary-action">Export JSON</button>
                </div>
                {saveLayer.data && <div className="w-full text-xs text-green-400">Saved layer: {saveLayer.data.name}</div>}
                {saveLayer.error && <div className="w-full text-xs text-red-300">{String(saveLayer.error)}</div>}
              </section>

              <section className="grid gap-3 lg:grid-cols-4">
                <Metric label="Assets" value={result.asset_count} />
                <Metric label="Internet Facing" value={result.exposure_counts.internet ?? 0} />
                <Metric label="High / Critical" value={(result.risk_counts.high ?? 0) + (result.risk_counts.critical ?? 0)} />
                <Metric label="Provider" value={result.provider ?? 'baseline'} compact />
              </section>

              <Panel title="Executive Summary">
                <p className="text-sm leading-6 text-gray-300">{result.summary}</p>
                <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
                  {Object.entries(result.exposure_counts).map(([key, value]) => <Chip key={key}>{key}: {value}</Chip>)}
                  {Object.entries(result.risk_counts).map(([key, value]) => <Chip key={key}>{key}: {value}</Chip>)}
                </div>
              </Panel>

              <section className="grid gap-5 xl:grid-cols-[1fr_360px]">
                <Panel title="Attack Surface Matrix">
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <select className="field max-w-[180px]" value={riskFilter} onChange={event => setRiskFilter(event.target.value)}>
                      <option value="all">All risk</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                    <select className="field max-w-[180px]" value={exposureFilter} onChange={event => setExposureFilter(event.target.value)}>
                      <option value="all">All exposure</option>
                      <option value="internet">Internet</option>
                      <option value="internal">Internal</option>
                      <option value="third-party">Third-party</option>
                      <option value="unknown">Unknown</option>
                    </select>
                    <span className="text-xs text-gray-500">{filteredAssets.length} rows</span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[1100px] text-left text-xs">
                      <thead className="border-b border-gray-800 text-gray-500">
                        <tr>
                          <th className="py-2 pr-3">Asset</th>
                          <th className="py-2 pr-3">Risk</th>
                          <th className="py-2 pr-3">Exposure</th>
                          <th className="py-2 pr-3">Entry Points</th>
                          <th className="py-2 pr-3">TTPs</th>
                          <th className="py-2 pr-3">Priority Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800">
                        {filteredAssets.map(asset => <AssetRow key={asset.asset_id} asset={asset} />)}
                      </tbody>
                    </table>
                  </div>
                </Panel>

                <div className="space-y-5">
                  <Panel title="Top Risks">
                    <div className="space-y-2">
                      {result.top_risks.slice(0, 6).map(asset => (
                        <div key={asset.asset_id} className="rounded border border-gray-800 bg-gray-950 p-3">
                          <div className="flex items-start justify-between gap-3">
                            <b className="text-sm text-white">{asset.asset}</b>
                            <RiskBadge level={asset.risk_level} score={asset.risk_score} />
                          </div>
                          <p className="mt-2 text-xs leading-5 text-gray-500">{asset.attack_surface.join(', ')}</p>
                        </div>
                      ))}
                    </div>
                  </Panel>
                  <Panel title="Validation Gaps">
                    <List items={result.validation_gaps.length ? result.validation_gaps : ['Validate inventory with active scanner, cloud inventory, DNS, EDR, and firewall telemetry.']} />
                  </Panel>
                  <Panel title="Cross-Asset Findings">
                    <List items={result.cross_asset_findings.length ? result.cross_asset_findings : result.recommended_workflow} />
                  </Panel>
                  <Panel title="Assumptions">
                    <List items={result.assumptions.length ? result.assumptions : ['No AI assumptions returned. Treat inventory fields as unverified until scanner, CMDB, cloud, identity, and network telemetry confirm them.']} />
                  </Panel>
                </div>
              </section>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="mx-auto mt-12 max-w-3xl rounded border border-gray-800 bg-gray-950 p-6">
      <h2 className="text-lg font-semibold text-white">Upload an asset inventory to build an attack surface matrix.</h2>
      <p className="mt-3 text-sm leading-6 text-gray-400">
        Supported inputs include CSV/JSON CMDB exports, cloud asset lists, scanner output, and plain hostname/IP lists.
        The module normalizes assets, scores exposure, proposes likely entry points and ATT&CK candidates, and uses AI to
        explain attack paths and validation gaps.
      </p>
    </div>
  );
}

function AssetRow({ asset }: { asset: AssetSurfaceAsset }) {
  return (
    <>
      <tr className="align-top">
        <td className="py-3 pr-3">
          <div className="font-semibold text-white">{asset.asset}</div>
          <div className="mt-1 text-[11px] text-gray-500">{asset.asset_type} · {asset.environment} · {asset.owner || 'no owner'}</div>
          <div className="mt-1 max-w-[240px] truncate font-mono text-[11px] text-gray-600">
            {[...asset.domains, ...asset.ip_addresses].length ? (
              [...asset.domains, ...asset.ip_addresses].map(value => (
                <IocLink key={value} value={value} source="AssetSurface" className="mr-1 hover:text-cyan-300 hover:underline" />
              ))
            ) : asset.asset_id}
          </div>
        </td>
        <td className="py-3 pr-3"><RiskBadge level={asset.risk_level} score={asset.risk_score} /></td>
        <td className="py-3 pr-3"><Chip>{asset.exposure}</Chip></td>
        <td className="py-3 pr-3 text-gray-400">{asset.likely_entry_points.join(', ')}</td>
        <td className="py-3 pr-3">
          <div className="flex flex-wrap gap-1">
            {asset.ttp_candidates.map(ttp => (
              <TtpLink
                key={`${asset.asset_id}-${ttp.attack_id}`}
                id={ttp.attack_id}
                className="rounded border border-mitre-accent/50 bg-mitre-accent/10 px-1.5 py-0.5 text-[10px] font-semibold text-mitre-accent hover:bg-mitre-accent/20"
                title={ttp.reason}
              >
                {ttp.attack_id}
              </TtpLink>
            ))}
          </div>
        </td>
        <td className="py-3 pr-3 text-gray-400">{asset.priority_actions.slice(0, 2).join(' ')}</td>
      </tr>
      <tr className="border-t-0 align-top">
        <td colSpan={6} className="pb-4 pr-3">
          <div className="grid gap-3 rounded border border-gray-800 bg-gray-950 p-3 text-xs md:grid-cols-3">
            <DetailBlock title="Attack Paths" items={asset.attack_paths?.length ? asset.attack_paths : asset.attack_surface} />
            <DetailBlock title="Control Gaps" items={asset.control_gaps?.length ? asset.control_gaps : ['Validate controls against scanner, CMDB, cloud, identity, and EDR telemetry.']} />
            <DetailBlock title="Detections / Validation" items={(asset.detection_ideas?.length ? asset.detection_ideas : asset.validation_steps) ?? asset.priority_actions} />
          </div>
        </td>
      </tr>
    </>
  );
}

function Metric({ label, value, compact = false }: { label: string; value: string | number; compact?: boolean }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950 p-4">
      <div className={`${compact ? 'text-xl' : 'text-3xl'} font-bold text-white`}>{value}</div>
      <div className="mt-1 text-xs font-semibold uppercase tracking-wide text-gray-500">{label}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded border border-gray-800 bg-gray-900/60">
      <div className="border-b border-gray-800 px-4 py-3">
        <h2 className="text-sm font-semibold text-white">{title}</h2>
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

function RiskBadge({ level, score }: { level: string; score: number }) {
  const color = level === 'critical'
    ? 'border-red-500 bg-red-950 text-red-300'
    : level === 'high'
      ? 'border-orange-500 bg-orange-950 text-orange-300'
      : level === 'medium'
        ? 'border-yellow-600 bg-yellow-950 text-yellow-300'
        : 'border-green-700 bg-green-950 text-green-300';
  return <span className={`inline-flex rounded border px-2 py-1 text-[11px] font-bold ${color}`}>{level} · {score}</span>;
}

function Chip({ children }: { children: ReactNode }) {
  return <span className="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-[11px] text-gray-300">{children}</span>;
}

function List({ items }: { items: string[] }) {
  return (
    <ul className="space-y-2 text-xs leading-5 text-gray-400">
      {items.map((item, index) => <li key={`${index}-${item}`} className="border-t border-gray-800 pt-2 first:border-t-0 first:pt-0">{item}</li>)}
    </ul>
  );
}

function DetailBlock({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <div className="mb-2 font-semibold uppercase tracking-wide text-gray-500">{title}</div>
      <ul className="space-y-1.5 text-gray-400">
        {items.slice(0, 4).map((item, index) => <li key={`${title}-${index}-${item}`}>{item}</li>)}
      </ul>
    </div>
  );
}

function loadAssetSurfaceHistory(): AssetSurfaceHistoryItem[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.localStorage.getItem(ASSET_SURFACE_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isAssetSurfaceHistoryItem).slice(0, ASSET_SURFACE_HISTORY_LIMIT);
  } catch {
    return [];
  }
}

function saveAssetSurfaceHistory(items: AssetSurfaceHistoryItem[]) {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(ASSET_SURFACE_HISTORY_KEY, JSON.stringify(items.slice(0, ASSET_SURFACE_HISTORY_LIMIT)));
  } catch {
    // Local history is a convenience feature; analysis results should still render if storage is unavailable.
  }
}

function createAssetSurfaceHistoryItem(result: AssetSurfaceAnalysisResult, fallbackName: string): AssetSurfaceHistoryItem {
  const createdAt = new Date().toISOString();
  const id = typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const uniqueTtps = new Set(result.assets.flatMap(asset => asset.ttp_candidates.map(ttp => ttp.attack_id.toUpperCase())));
  const highOrCritical = result.assets.filter(asset => ['high', 'critical'].includes(asset.risk_level) || ['high', 'critical'].includes(asset.ai_risk_level ?? '')).length;
  return {
    ...result,
    history_id: id,
    created_at: createdAt,
    name: result.inventory_name || result.filename || fallbackName || `Asset surface ${new Date(createdAt).toLocaleString()}`,
    ttp_count: uniqueTtps.size,
    high_or_critical_count: highOrCritical,
  };
}

function isAssetSurfaceHistoryItem(value: unknown): value is AssetSurfaceHistoryItem {
  if (!value || typeof value !== 'object') return false;
  const item = value as Partial<AssetSurfaceHistoryItem>;
  return (
    typeof item.history_id === 'string' &&
    typeof item.created_at === 'string' &&
    typeof item.name === 'string' &&
    Array.isArray(item.assets) &&
    typeof item.asset_count === 'number' &&
    typeof item.summary === 'string'
  );
}

function downloadJson(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'asset-surface';
}
