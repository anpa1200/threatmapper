import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { aptApi, attackApi, analyzeApi, iocApi, operationsApi, type IOCItem, type Investigation } from '@/api/client';
import { useAppStore } from '@/store';
import { Header } from '@/components/Layout/Header';

type Provider = 'local' | 'claude' | 'openai' | 'gemini' | 'minimax';
type ReportFormat = 'md' | 'txt' | 'pdf';
type ReportSections = {
  navigator: boolean;
  ttps: boolean;
  actors: boolean;
  iocs: boolean;
};
type ReportRow = {
  id: string;
  name: string;
  assessment: {
    evidence?: string;
    source?: string;
    confidence?: string;
    mapping?: string;
    notes?: string;
    maturity?: string;
  };
  covered: boolean;
};

const providerOptions: { id: Provider; label: string }[] = [
  { id: 'local', label: 'Local LLM' },
  { id: 'claude', label: 'Claude' },
  { id: 'openai', label: 'OpenAI' },
  { id: 'gemini', label: 'Gemini' },
  { id: 'minimax', label: 'MiniMax' },
];

export function InvestigationReport() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { domain, version, selectedTechniques, coverageTechniques, techniqueAssessments, replaceTechniques } = useAppStore();
  const ids = useMemo(() => [...selectedTechniques].sort(), [selectedTechniques]);
  const [activeInvestigationId, setActiveInvestigationId] = useState('');
  const [newInvestigationName, setNewInvestigationName] = useState('');
  const [sections, setSections] = useState<ReportSections>({
    navigator: true,
    ttps: true,
    actors: true,
    iocs: true,
  });
  const [provider, setProvider] = useState<Provider>('local');
  const [reportTitle, setReportTitle] = useState('AdversaryGraph Investigation Report');
  const [generatedReport, setGeneratedReport] = useState('');
  const [aiSummary, setAiSummary] = useState('');
  const [isAiGenerating, setIsAiGenerating] = useState(false);
  const [isSummaryGenerating, setIsSummaryGenerating] = useState(false);
  const [aiError, setAiError] = useState('');
  const [workflowMessage, setWorkflowMessage] = useState('');
  const { data: investigations = [] } = useQuery({
    queryKey: ['operations-investigations'],
    queryFn: operationsApi.investigations,
  });
  const activeInvestigation = useMemo(
    () => investigations.find(item => item.id === activeInvestigationId) ?? investigations[0] ?? null,
    [activeInvestigationId, investigations],
  );
  const investigationIds = useMemo(
    () => Array.from(new Set([...(activeInvestigation?.technique_ids ?? []), ...ids])).sort(),
    [activeInvestigation, ids],
  );
  const createInvestigation = useMutation({
    mutationFn: () => operationsApi.createInvestigation({
      name: newInvestigationName.trim() || `Investigation ${new Date().toLocaleString()}`,
      description: 'Structured AdversaryGraph investigation workspace.',
      status: 'active',
      domain,
      actor_ids: [],
      technique_ids: ids,
      report_ids: [],
      evidence_nodes: [],
      evidence_edges: [],
      timeline: [{ at: new Date().toISOString(), event: 'Investigation created' }],
    }),
    onSuccess: row => {
      setActiveInvestigationId(row.id);
      setNewInvestigationName('');
      queryClient.invalidateQueries({ queryKey: ['operations-investigations'] });
    },
  });

  const { data: techniques = [] } = useQuery({
    queryKey: ['report-techniques', domain, version],
    queryFn: () => attackApi.techniques({ domain, version: version ?? undefined }),
  });
  const { data: matches = [], isFetching: matchesLoading } = useQuery({
    queryKey: ['report-matches', domain, version, investigationIds.join(',')],
    queryFn: () => aptApi.compare({ technique_ids: investigationIds, domain, version: version ?? undefined, top_n: 10 }),
    enabled: investigationIds.length > 0,
  });

  const actorIocQueries = useQueries({
    queries: sections.iocs
      ? matches.slice(0, 5).map(match => ({
        queryKey: ['report-actor-iocs', match.group_attack_id],
        queryFn: () => iocApi.actor(match.group_attack_id, { days: 180, active_only: true, limit: 20 }),
        enabled: investigationIds.length > 0,
      }))
      : [],
  });

  const rows = useMemo(() => investigationIds.map(id => ({
    id,
    name: techniques.find(item => item.attack_id === id)?.name ?? id,
    assessment: techniqueAssessments[id] ?? {},
    covered: coverageTechniques.has(id),
  })), [coverageTechniques, investigationIds, techniqueAssessments, techniques]);

  const relevantIocs = useMemo(
    () => actorIocQueries.flatMap(query => (query.data ?? []) as IOCItem[]),
    [actorIocQueries],
  );
  const localReport = useMemo(
    () => buildLocalReport({ title: reportTitle, domain, rows, matches, relevantIocs, sections, investigation: activeInvestigation }),
    [activeInvestigation, domain, matches, relevantIocs, reportTitle, rows, sections],
  );
  const activeReport = generatedReport || localReport;
  const selectedSectionCount = Object.values(sections).filter(Boolean).length;

  const updateActiveInvestigation = useMutation({
    mutationFn: (body: Omit<Investigation, 'id' | 'created_at' | 'updated_at'>) => {
      if (!activeInvestigation) throw new Error('Create or select an investigation first.');
      return operationsApi.updateInvestigation(activeInvestigation.id, body);
    },
    onSuccess: row => {
      setActiveInvestigationId(row.id);
      queryClient.invalidateQueries({ queryKey: ['operations-investigations'] });
    },
  });

  const toggleSection = (key: keyof ReportSections) => {
    setSections(current => ({ ...current, [key]: !current[key] }));
  };

  const openLayerOnMatrix = () => {
    if (!investigationIds.length) return;
    replaceTechniques(investigationIds);
    setWorkflowMessage(`Loaded ${investigationIds.length} investigation TTPs into the matrix.`);
    navigate('/navigator');
  };

  const compareAndSave = async () => {
    if (!activeInvestigation || !investigationIds.length) {
      setWorkflowMessage('Create/select an investigation and add TTPs before comparing.');
      return;
    }
    setWorkflowMessage('');
    try {
      const results = await aptApi.compare({ technique_ids: investigationIds, domain, version: version ?? undefined, top_n: 10 });
      await updateActiveInvestigation.mutateAsync(mergeInvestigation(activeInvestigation, {
        actor_ids: results.slice(0, 10).map(item => item.group_attack_id),
        evidence_nodes: [{
          id: `actor-comparison:${Date.now()}`,
          type: 'actor-comparison',
          label: 'Threat actor TTP comparison',
          summary: `Compared ${investigationIds.length} investigation TTPs against known actor profiles.`,
          results: results.slice(0, 10),
        }],
        timeline: [{
          at: new Date().toISOString(),
          event: `Compared investigation TTP layer with threat actors (${results.length} results)`,
          source: 'Investigation',
          technique_count: investigationIds.length,
        }],
      }));
      replaceTechniques(investigationIds);
      setWorkflowMessage(`Saved ${Math.min(results.length, 10)} actor-comparison leads to ${activeInvestigation.name}.`);
    } catch (error) {
      setWorkflowMessage(error instanceof Error ? error.message : String(error));
    }
  };

  const summarizeInvestigation = async () => {
    if (!activeInvestigation || !investigationIds.length) {
      setWorkflowMessage('Create/select an investigation and add evidence before AI summary.');
      return;
    }
    setIsSummaryGenerating(true);
    setAiError('');
    setWorkflowMessage('');
    try {
      const context = buildReportContext({ domain, rows, matches, relevantIocs, sections, investigation: activeInvestigation });
      const response = await analyzeApi.chat({
        provider,
        context,
        message: [
          `Summarize the active investigation "${activeInvestigation.name}".`,
          'Use this structure: current assessment, strongest evidence, IOC findings, TTP layer, actor-comparison leads, caveats, and next actions.',
          'Use only the provided evidence. Do not claim attribution. Separate direct evidence from enrichment leads.',
        ].join(' '),
      });
      const summary = (await readSseText(response)).trim() || 'AI summary returned no content.';
      setAiSummary(summary);
      await updateActiveInvestigation.mutateAsync(mergeInvestigation(activeInvestigation, {
        evidence_nodes: [{
          id: `ai-summary:${Date.now()}`,
          type: 'ai-summary',
          label: 'AI investigation summary',
          summary,
          provider,
        }],
        timeline: [{
          at: new Date().toISOString(),
          event: 'Generated AI investigation summary',
          source: provider,
          technique_count: investigationIds.length,
        }],
      }));
      setWorkflowMessage(`AI summary saved to ${activeInvestigation.name}.`);
    } catch (error) {
      setAiError(error instanceof Error ? error.message : String(error));
    } finally {
      setIsSummaryGenerating(false);
    }
  };

  const generateLocal = () => {
    setAiError('');
    setGeneratedReport(localReport);
  };

  const generateWithAi = async () => {
    if (!investigationIds.length || !selectedSectionCount) return;
    setIsAiGenerating(true);
    setAiError('');
    setGeneratedReport('');
    try {
      const context = buildReportContext({ domain, rows, matches, relevantIocs, sections, investigation: activeInvestigation });
      const response = await analyzeApi.chat({
        provider,
        context,
        message: [
          `Generate a professional threat intelligence investigation report titled "${reportTitle}".`,
          'Use only the provided context. Do not invent evidence, IOCs, actors, or TTPs.',
          'Write in Markdown with these sections when data exists: Executive Summary, Scope, Navigator Layer, ATT&CK TTP Evidence, Threat Actor Comparison, Relevant IOC Enrichment, Detection and Coverage Priorities, Analytic Caveats.',
          'Make it client-ready, concise, and actionable.',
        ].join(' '),
      });
      const text = await readSseText(response);
      const report = text.trim() || localReport;
      setGeneratedReport(report);
      if (activeInvestigation) {
        await updateActiveInvestigation.mutateAsync(mergeInvestigation(activeInvestigation, {
          evidence_nodes: [{
            id: `investigation-report:${Date.now()}`,
            type: 'investigation-report',
            label: reportTitle,
            summary: truncate(report.replace(/\s+/g, ' '), 500),
            provider,
          }],
          timeline: [{
            at: new Date().toISOString(),
            event: `Generated investigation report: ${reportTitle}`,
            source: provider,
            technique_count: investigationIds.length,
          }],
        }));
      }
    } catch (error) {
      setAiError(error instanceof Error ? error.message : String(error));
    } finally {
      setIsAiGenerating(false);
    }
  };

  const download = (format: ReportFormat) => {
    const filenameBase = slug(reportTitle || 'adversarygraph-investigation-report');
    if (format === 'pdf') {
      const pdf = buildSimplePdf(markdownToPlainText(activeReport));
      downloadBlob(pdf, `${filenameBase}.pdf`, 'application/pdf');
      return;
    }
    const content = format === 'txt' ? markdownToPlainText(activeReport) : activeReport;
    downloadBlob(content, `${filenameBase}.${format}`, format === 'md' ? 'text/markdown' : 'text/plain');
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="Investigation" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <Panel title="Investigation flow">
            <div className="grid gap-3 p-3 lg:grid-cols-3">
              <FlowStep number={1} title="Create new investigation" text="Open a case workspace before analysis so every result has a destination." />
              <FlowStep number={2} title="Analyze logs one by one" text="Open AI Analysis Log / PCAP mode. Analyze firewall logs first, then EDR logs as a separate run. No manual prompt is needed." actionLabel="Open AI Analysis" onAction={() => navigate('/analyze')} />
              <FlowStep number={3} title="Add each result to my investigation" text="After each log analysis run, use Add to investigation and choose this case." />
              <FlowStep number={4} title="Do additional IOC investigations" text="Investigate extracted IOCs and add useful IOC results back to the same case." actionLabel="Open IOC Investigation" onAction={() => navigate('/ioc-investigation')} />
              <FlowStep number={5} title="Keep investigation structured" text="Review logs, reports, TTP layer, IOC list, evidence nodes, and timeline below." />
              <FlowStep number={6} title="Create Navigator-like TTP layer" text="Send all investigation TTPs to the ATT&CK matrix." actionLabel="Send to matrix" onAction={openLayerOnMatrix} disabled={!investigationIds.length} />
              <FlowStep number={7} title="Compare TTPs with threat actors" text="Compare the investigation layer and save overlap leads to this case." actionLabel="Compare + save" onAction={() => void compareAndSave()} disabled={!activeInvestigation || !investigationIds.length || updateActiveInvestigation.isPending} />
              <FlowStep number={8} title="Summarize investigation with AI" text="Summarize saved evidence, TTPs, IOCs, actor leads, and caveats." actionLabel={isSummaryGenerating ? 'Summarizing...' : 'Summarize'} onAction={() => void summarizeInvestigation()} disabled={!activeInvestigation || !investigationIds.length || isSummaryGenerating} />
              <FlowStep number={9} title="Create investigation report" text="Generate a local or AI-assisted report, then export PDF / Markdown / TXT." />
            </div>
            {(workflowMessage || updateActiveInvestigation.error) && (
              <div className="border-t border-gray-800 px-4 py-3 text-xs">
                {workflowMessage && <p className="text-green-300">{workflowMessage}</p>}
                {updateActiveInvestigation.error && (
                  <p className="text-red-300">{updateActiveInvestigation.error instanceof Error ? updateActiveInvestigation.error.message : String(updateActiveInvestigation.error)}</p>
                )}
              </div>
            )}
          </Panel>

          <Panel title="Investigation workspace">
            <div className="grid gap-4 p-3 xl:grid-cols-[420px_minmax(0,1fr)]">
              <div className="space-y-3">
                <div className="grid grid-cols-[1fr_auto] gap-2">
                  <input
                    value={newInvestigationName}
                    onChange={event => setNewInvestigationName(event.target.value)}
                    placeholder="New investigation name"
                    className="field"
                  />
                  <button
                    type="button"
                    onClick={() => createInvestigation.mutate()}
                    disabled={createInvestigation.isPending}
                    className="primary-action disabled:opacity-50"
                  >
                    Open the new investigation
                  </button>
                </div>
                <select
                  value={activeInvestigation?.id ?? ''}
                  onChange={event => setActiveInvestigationId(event.target.value)}
                  className="field w-full"
                >
                  {investigations.length ? investigations.map(item => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  )) : <option value="">No investigation yet</option>}
                </select>
                {createInvestigation.error && (
                  <p className="rounded border border-red-500/50 bg-red-950/30 p-2 text-xs text-red-200">
                    {createInvestigation.error instanceof Error ? createInvestigation.error.message : String(createInvestigation.error)}
                  </p>
                )}
              </div>
              <InvestigationStructure
                investigation={activeInvestigation}
                rows={rows}
                selectedTechniqueCount={ids.length}
                onOpenTtp={id => {
                  replaceTechniques([id]);
                  navigate('/navigator');
                }}
                onOpenAllTtps={openLayerOnMatrix}
                onInvestigateIoc={value => navigate(`/ioc-investigation?indicator=${encodeURIComponent(value)}`)}
                onSearchIoc={value => navigate(`/ioc-library?search=${encodeURIComponent(value)}`)}
              />
            </div>
          </Panel>

          <section className="grid gap-5 xl:grid-cols-[420px_minmax(0,1fr)]">
            <div className="space-y-5">
              <Panel title="Report builder">
                <div className="space-y-4 p-3">
                  <label className="block">
                    <span className="mb-1 block text-xs font-semibold uppercase text-gray-500">Report title</span>
                    <input value={reportTitle} onChange={event => setReportTitle(event.target.value)} className="field w-full" />
                  </label>

                  <div>
                    <div className="mb-2 text-xs font-semibold uppercase text-gray-500">Include platform actions</div>
                    <div className="space-y-2">
                      <CheckRow
                        checked={sections.navigator}
                        title="Navigator"
                        text="Current matrix context, selected TTP count, covered TTPs, and coverage gaps."
                        onChange={() => toggleSection('navigator')}
                      />
                      <CheckRow
                        checked={sections.ttps}
                        title="TTPs"
                        text="Selected ATT&CK techniques, analyst evidence, mapping confidence, and maturity."
                        onChange={() => toggleSection('ttps')}
                      />
                      <CheckRow
                        checked={sections.actors}
                        title="Comparison with threat actors"
                        text="Behavior-overlap hypotheses from selected TTPs against actor profiles."
                        onChange={() => toggleSection('actors')}
                      />
                      <CheckRow
                        checked={sections.iocs}
                        title="Relevant IOC enrichment"
                        text="Recent actor-linked IOCs, malware family context, source, confidence, and mapped TTPs."
                        onChange={() => toggleSection('iocs')}
                      />
                    </div>
                  </div>

                  <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
                    <div className="mb-2 text-xs font-semibold uppercase text-gray-500">Generation mode</div>
                    <div className="mb-2 grid grid-cols-3 gap-2">
                      <button
                        type="button"
                        onClick={openLayerOnMatrix}
                        disabled={!investigationIds.length}
                        className="secondary-action disabled:opacity-40"
                      >
                        Put TTPs on matrix
                      </button>
                      <button
                        type="button"
                        onClick={() => void compareAndSave()}
                        disabled={!activeInvestigation || !investigationIds.length || updateActiveInvestigation.isPending}
                        className="secondary-action disabled:opacity-40"
                      >
                        Compare + save result
                      </button>
                      <button
                        type="button"
                        onClick={() => void summarizeInvestigation()}
                        disabled={!activeInvestigation || !investigationIds.length || isSummaryGenerating}
                        className="primary-action disabled:opacity-40"
                      >
                        {isSummaryGenerating ? 'Summarizing...' : 'Complete AI analysis'}
                      </button>
                    </div>
                    <button
                      type="button"
                      onClick={generateLocal}
                      disabled={!investigationIds.length || !selectedSectionCount}
                      className="secondary-action mb-2 w-full disabled:opacity-40"
                    >
                      Generate locally from selected sections
                    </button>
                    <div className="grid grid-cols-[1fr_auto] gap-2">
                      <select value={provider} onChange={event => setProvider(event.target.value as Provider)} className="field">
                        {providerOptions.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}
                      </select>
                      <button
                        type="button"
                        onClick={generateWithAi}
                        disabled={!investigationIds.length || !selectedSectionCount || isAiGenerating}
                        className="primary-action disabled:opacity-40"
                      >
                        {isAiGenerating ? 'Generating...' : 'AI assistant'}
                      </button>
                    </div>
                    <p className="mt-2 text-[10px] leading-4 text-gray-500">
                      AI mode sends the selected Navigator/TTP/actor/IOC parameters to the configured LLM and writes a client-ready report.
                    </p>
                    {aiError && <p className="mt-2 rounded border border-red-500/50 bg-red-950/30 p-2 text-xs text-red-200">{aiError}</p>}
                  </div>
                </div>
              </Panel>

              <Panel title="Download">
                <div className="grid grid-cols-3 gap-2 p-3">
                  <button type="button" onClick={() => download('pdf')} disabled={!activeReport.trim()} className="secondary-action disabled:opacity-40">PDF</button>
                  <button type="button" onClick={() => download('md')} disabled={!activeReport.trim()} className="secondary-action disabled:opacity-40">MD</button>
                  <button type="button" onClick={() => download('txt')} disabled={!activeReport.trim()} className="secondary-action disabled:opacity-40">TXT</button>
                </div>
              </Panel>

              <Panel title="Report inputs">
                <div className="grid grid-cols-2 gap-2 p-3">
                  <Metric label="Selected TTPs" value={rows.length} />
                  <Metric label="Covered TTPs" value={rows.filter(row => row.covered).length} />
                  <Metric label="Actor matches" value={matches.length} />
                  <Metric label="Relevant IOCs" value={relevantIocs.length} />
                </div>
                {matchesLoading && <p className="px-3 pb-3 text-xs text-gray-500">Loading actor comparison...</p>}
                {!investigationIds.length && <p className="px-3 pb-3 text-xs text-amber-300">Select TTPs or add analytic results to an investigation before generating a report.</p>}
              </Panel>

              {aiSummary && (
                <Panel title="AI investigation summary">
                  <pre className="max-h-72 overflow-auto whitespace-pre-wrap p-4 text-xs leading-6 text-gray-300">{aiSummary}</pre>
                </Panel>
              )}
            </div>

            <Panel title="Report preview">
              <pre className="max-h-[calc(100vh-220px)] overflow-auto whitespace-pre-wrap p-4 text-xs leading-6 text-gray-300">
                {activeReport || 'No report content yet.'}
              </pre>
            </Panel>
          </section>

          {rows.length > 0 && (
            <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_420px]">
              <Panel title="Selected TTP evidence">
                <div className="divide-y divide-gray-800">
                  {rows.map(row => (
                    <div key={row.id} className="p-3">
                      <div className="flex items-start justify-between gap-3">
                        <b className="text-sm text-gray-200"><span className="mr-2 font-mono text-mitre-accent">{row.id}</span>{row.name}</b>
                        <span className={`text-[10px] ${row.covered ? 'text-green-400' : 'text-amber-500'}`}>{row.covered ? 'covered' : 'gap'}</span>
                      </div>
                      <p className="mt-1 text-[10px] text-gray-500">
                        {row.assessment.mapping ?? 'weak'} mapping · {row.assessment.confidence ?? 'low'} confidence · {row.assessment.maturity ?? 'none'} maturity
                      </p>
                      {row.assessment.evidence && <p className="mt-1 text-xs text-gray-400">{row.assessment.evidence}</p>}
                    </div>
                  ))}
                </div>
              </Panel>
              <Panel title="Threat actor comparison">
                <div className="divide-y divide-gray-800">
                  {matches.map((item, index) => (
                    <div key={item.group_attack_id} className="p-3">
                      <b className="text-xs text-gray-300">{index + 1}. {item.group_name}</b>
                      <p className="mt-1 text-[10px] text-gray-500">
                        {item.group_attack_id} · {Math.round(item.similarity * 100)}% Jaccard · {item.shared_count} shared
                      </p>
                    </div>
                  ))}
                  {!matches.length && <p className="p-3 text-xs text-gray-500">No actor comparison yet.</p>}
                </div>
              </Panel>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}

function buildLocalReport({
  title,
  domain,
  rows,
  matches,
  relevantIocs,
  sections,
  investigation,
}: {
  title: string;
  domain: string;
  rows: ReportRow[];
  matches: Array<{ group_attack_id: string; group_name: string; similarity: number; shared_count: number; shared_techniques: string[] }>;
  relevantIocs: IOCItem[];
  sections: ReportSections;
  investigation: Investigation | null;
}) {
  const covered = rows.filter(row => row.covered).length;
  const lines: string[] = [
    `# ${title || 'AdversaryGraph Investigation Report'}`,
    '',
    `Generated: ${new Date().toISOString()}`,
    `Domain: ${domain}`,
    `Selected techniques: ${rows.length}`,
    `Covered techniques: ${covered}`,
    `Coverage gaps: ${Math.max(0, rows.length - covered)}`,
    '',
    '## Executive Summary',
    '',
    rows.length
      ? `This report summarizes ${rows.length} selected ATT&CK techniques, ${matches.length} behavior-overlap actor hypotheses, and ${relevantIocs.length} relevant IOC enrichment records available in AdversaryGraph.`
      : 'No selected techniques were available. Select TTPs or load a workspace before generating the report.',
    '',
  ];
  if (sections.navigator) {
    lines.push('## Navigator', '', `- Current domain: ${domain}`, `- Selected TTPs: ${rows.length}`, `- Covered TTPs: ${covered}`, `- Coverage gaps: ${Math.max(0, rows.length - covered)}`, '');
  }
  if (sections.ttps) {
    lines.push('## ATT&CK TTP Evidence', '');
    rows.forEach(row => {
      lines.push(
        `### ${row.id} - ${row.name}`,
        `- Coverage: ${row.covered ? 'covered' : 'gap'}`,
        `- Mapping: ${row.assessment.mapping ?? 'weak'}`,
        `- Confidence: ${row.assessment.confidence ?? 'low'}`,
        `- Maturity: ${row.assessment.maturity ?? 'none'}`,
        `- Evidence: ${row.assessment.evidence ?? 'Not recorded'}`,
        `- Source: ${row.assessment.source ?? 'Not recorded'}`,
        `- Notes: ${row.assessment.notes ?? 'Not recorded'}`,
        '',
      );
    });
  }
  if (investigation) {
    const logNodes = investigation.evidence_nodes.filter(item => String(item.type ?? '').includes('log'));
    const reportNodes = investigation.evidence_nodes.filter(item => String(item.type ?? '').includes('report') || String(item.type ?? '').includes('analysis'));
    const iocNodes = investigation.evidence_nodes.filter(item => String(item.type ?? '').includes('ioc') || String(item.type ?? '').includes('indicator'));
    lines.push('## Investigation Workspace', '', `Investigation: ${investigation.name}`, `Status: ${investigation.status}`, '');
    lines.push('### Logs - Result Analysis', '');
    if (logNodes.length) logNodes.slice(0, 20).forEach(node => lines.push(`- ${String(node.label ?? node.value ?? node.id ?? 'Log analysis')} - ${String(node.summary ?? node.description ?? '')}`));
    else lines.push('- No log analysis evidence has been added yet.');
    lines.push('', '### Report Analysis', '');
    if (reportNodes.length) reportNodes.slice(0, 20).forEach(node => lines.push(`- ${String(node.label ?? node.value ?? node.id ?? 'Report analysis')} - ${String(node.summary ?? node.description ?? '')}`));
    else lines.push('- No report analysis evidence has been added yet.');
    lines.push('', '### IOC List', '');
    if (iocNodes.length) iocNodes.slice(0, 60).forEach(node => lines.push(`- ${String(node.value ?? node.label ?? node.id)} (${String(node.ioc_type ?? node.type ?? 'ioc')})`));
    else lines.push('- No IOC evidence nodes have been added yet.');
    lines.push('', '### Timeline', '');
    if (investigation.timeline.length) investigation.timeline.slice(-20).forEach(item => lines.push(`- ${String(item.at ?? '')}: ${String(item.event ?? item.source ?? 'Investigation event')}`));
    else lines.push('- No timeline events yet.');
    lines.push('');
  }
  if (sections.actors) {
    lines.push('## Comparison With Threat Actors', '');
    if (matches.length) {
      matches.forEach((item, index) => {
        lines.push(
          `${index + 1}. ${item.group_name} (${item.group_attack_id})`,
          `   - Similarity: ${Math.round(item.similarity * 100)}% Jaccard overlap`,
          `   - Shared TTPs: ${item.shared_count}`,
          `   - Shared technique IDs: ${item.shared_techniques.join(', ') || 'None'}`,
        );
      });
    } else {
      lines.push('No behavior-overlap actor hypotheses were available.');
    }
    lines.push('');
  }
  if (sections.iocs) {
    lines.push('## Relevant IOC Enrichment', '');
    if (relevantIocs.length) {
      relevantIocs.slice(0, 60).forEach(item => {
        lines.push(
          `- ${item.value} (${item.type})`,
          `  - Source: ${item.source || 'unknown'}`,
          `  - Malware: ${item.malware_family || 'unknown'}`,
          `  - Campaign: ${item.campaign || 'unknown'}`,
          `  - TTPs: ${item.technique_ids?.join(', ') || 'none mapped'}`,
          `  - Confidence: ${item.confidence ?? 0}`,
        );
      });
    } else {
      lines.push('No actor-linked IOC enrichment records were available for the current comparison set.');
    }
    lines.push('');
  }
  lines.push(
    '## Analytic Caveats',
    '',
    '- TTP overlap supports prioritization and hypothesis generation. It is not definitive attribution evidence.',
    '- IOC enrichment should be validated against source reports, timestamps, and local telemetry before operational use.',
    '- AI-generated report text must be analyst-reviewed before customer delivery.',
  );
  return lines.join('\n');
}

function InvestigationStructure({
  investigation,
  rows,
  selectedTechniqueCount,
  onOpenTtp,
  onOpenAllTtps,
  onInvestigateIoc,
  onSearchIoc,
}: {
  investigation: Investigation | null;
  rows: ReportRow[];
  selectedTechniqueCount: number;
  onOpenTtp: (id: string) => void;
  onOpenAllTtps: () => void;
  onInvestigateIoc: (value: string) => void;
  onSearchIoc: (value: string) => void;
}) {
  const nodes = investigation?.evidence_nodes ?? [];
  const logNodes = nodes.filter(item => String(item.type ?? '').includes('log'));
  const reportNodes = nodes.filter(item => String(item.type ?? '').includes('report') || String(item.type ?? '').includes('analysis'));
  const iocNodes = uniqueIocNodes(nodes);
  const behaviorNodes = uniqueSuspiciousBehaviorNodes(nodes);
  const ttpEvidenceNodes = uniqueTtpEvidenceNodes(nodes);
  const ttpRefsById = ttpEvidenceNodes.reduce((acc, item) => {
    acc.set(item.attackId, mergeArrays(acc.get(item.attackId) ?? [], [item.sourceRef]));
    return acc;
  }, new Map<string, string[]>());
  const ttpRows = rows.length
    ? rows
    : (investigation?.technique_ids ?? []).map(id => ({ id, name: id, covered: false, assessment: {} }));
  return (
    <div className="space-y-3">
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
        <InvestigationBucket title="Logs - result analysis" count={logNodes.length} text="Log / PCAP findings, suspicious commands, observables, and mapped behavior." />
        <InvestigationBucket title="Report analysis" count={reportNodes.length} text="CTI reports, uploaded analysis sessions, summaries, and source-backed TTPs." />
        <InvestigationBucket title="Suspicious behaviors" count={behaviorNodes.length} text="Expected behavior patterns found in logs, mapped to TTP and IOC leads." />
        <InvestigationBucket title="Founded TTP layer" count={investigation?.technique_ids.length ?? selectedTechniqueCount} text="Merged ATT&CK layer from Navigator, AI analysis, IOC investigation, and reports." />
        <InvestigationBucket title="IOC list" count={iocNodes.length} text="Extracted indicators, enrichment nodes, source records, and graph pivots." />
      </div>

      <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
        <div className="mb-2 flex items-center justify-between gap-2">
          <b className="text-xs text-gray-200">Log analysis results</b>
          <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{logNodes.length}</span>
        </div>
        {logNodes.length ? (
          <div className="grid gap-2 lg:grid-cols-2">
            {logNodes.slice(-20).map(node => (
              <div key={String(node.id ?? node.label)} className="rounded border border-gray-800 bg-gray-950 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <b className="text-sm text-gray-100">{String(node.label ?? 'Log / PCAP analysis')}</b>
                  <span className="rounded bg-cyan-950 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200">
                    {String(node.source_ref ?? node.analysis_id ?? 'log-source')}
                  </span>
                </div>
                <p className="mt-2 line-clamp-3 text-xs leading-5 text-gray-400">{String(node.summary ?? '')}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {Array.isArray(node.observables) && node.observables.slice(0, 8).map((observable, index) => {
                    const value = String((observable as Record<string, unknown>).value ?? '');
                    if (!value) return null;
                    return (
                      <button key={`${value}-${index}`} type="button" onClick={() => onInvestigateIoc(value)} className="max-w-[180px] truncate rounded border border-cyan-900 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200 hover:border-cyan-400" title={value}>
                        {value}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-gray-500">No Log / PCAP analysis results have been added to this investigation yet.</p>
        )}
      </div>

      <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
        <div className="mb-2 flex items-center justify-between gap-2">
          <b className="text-xs text-gray-200">Expected suspicious behaviors</b>
          <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{behaviorNodes.length}</span>
        </div>
        {behaviorNodes.length ? (
          <div className="max-h-72 overflow-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead className="bg-gray-950/70 text-[10px] uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="border-b border-gray-800 px-3 py-2">Evidence</th>
                  <th className="border-b border-gray-800 px-3 py-2">Why it matters</th>
                  <th className="border-b border-gray-800 px-3 py-2">TTP / IOC tags</th>
                </tr>
              </thead>
              <tbody>
                {behaviorNodes.map(node => (
                  <tr key={node.key} className="bg-red-950/10">
                    <td className="border-b border-gray-800 px-3 py-2 align-top">
                      <p className="font-medium text-gray-100">{node.evidence}</p>
                      {node.sourceRefs.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {node.sourceRefs.map(ref => (
                            <span key={ref} className="rounded bg-cyan-950 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200">{ref}</span>
                          ))}
                        </div>
                      )}
                      {node.refs.length > 0 && <p className="mt-1 line-clamp-2 font-mono text-[10px] text-gray-500">{node.refs[0]}</p>}
                    </td>
                    <td className="border-b border-gray-800 px-3 py-2 align-top text-gray-300">{node.why}</td>
                    <td className="border-b border-gray-800 px-3 py-2 align-top">
                      <div className="flex max-w-lg flex-wrap gap-1.5">
                        {node.ttps.map(id => (
                          <button
                            key={id}
                            type="button"
                            onClick={() => onOpenTtp(id)}
                            className="rounded border border-mitre-accent/50 bg-mitre-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-mitre-accent hover:bg-mitre-accent hover:text-white"
                          >
                            {id}
                          </button>
                        ))}
                        {node.iocs.map(value => (
                          <button
                            key={value}
                            type="button"
                            onClick={() => onInvestigateIoc(value)}
                            className="max-w-[220px] truncate rounded border border-cyan-700/60 bg-cyan-950/20 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200 hover:border-cyan-400"
                            title={value}
                          >
                            {value}
                          </button>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-gray-500">No expected suspicious behavior rows have been added to this investigation yet.</p>
        )}
      </div>

      <div className="grid gap-3 xl:grid-cols-2">
        <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <b className="text-xs text-gray-200">TTPs</b>
            <button
              type="button"
              onClick={onOpenAllTtps}
              disabled={!ttpRows.length}
              className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent disabled:opacity-40"
            >
              Open all on matrix
            </button>
          </div>
          <div className="max-h-52 overflow-auto">
            {ttpRows.length ? (
              <div className="flex flex-wrap gap-2">
                {ttpRows.map(row => (
                  <button
                    key={row.id}
                    type="button"
                    onClick={() => onOpenTtp(row.id)}
                    title={`Open ${row.id} on matrix`}
                    className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-left text-[11px] text-gray-200 hover:border-mitre-accent hover:text-white"
                  >
                    <span className="font-mono text-mitre-accent">{row.id}</span>
                    <span className="ml-1 text-gray-400">{row.name}</span>
                    {(ttpRefsById.get(row.id) ?? []).slice(0, 3).map(ref => (
                      <span key={`${row.id}-${ref}`} className="ml-1 rounded bg-cyan-950 px-1 py-0.5 font-mono text-[9px] text-cyan-200">{ref}</span>
                    ))}
                  </button>
                ))}
                {ttpEvidenceNodes.filter(item => !ttpRows.some(row => row.id === item.attackId)).map(item => (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => onOpenTtp(item.attackId)}
                    title={`Open ${item.attackId} on matrix`}
                    className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-left text-[11px] text-gray-200 hover:border-mitre-accent hover:text-white"
                  >
                    <span className="font-mono text-mitre-accent">{item.attackId}</span>
                    <span className="ml-1 text-gray-400">{item.label.replace(item.attackId, '').trim()}</span>
                    <span className="ml-1 rounded bg-cyan-950 px-1 py-0.5 font-mono text-[9px] text-cyan-200">{item.sourceRef}</span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-500">No TTPs have been added to this investigation yet.</p>
            )}
          </div>
        </div>

        <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <b className="text-xs text-gray-200">IOCs</b>
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{iocNodes.length}</span>
          </div>
          <div className="max-h-52 divide-y divide-gray-800 overflow-auto">
            {iocNodes.length ? iocNodes.map(node => (
              <div key={node.key} className="py-2">
                <button
                  type="button"
                  onClick={() => onInvestigateIoc(node.value)}
                  title={`Investigate ${node.value}`}
                  className="block w-full truncate text-left font-mono text-xs text-gray-100 hover:text-mitre-accent"
                >
                  {node.value}
                </button>
                <p className="mt-1 line-clamp-2 text-[10px] leading-4 text-gray-500">
                  {node.type} · {node.source || 'investigation evidence'}{node.description ? ` · ${node.description}` : ''}
                </p>
                <div className="mt-2 flex flex-wrap gap-2">
                  <button type="button" onClick={() => onInvestigateIoc(node.value)} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent">Investigate IOC</button>
                  <button type="button" onClick={() => onSearchIoc(node.value)} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent">Search IOC Library</button>
                </div>
              </div>
            )) : (
              <p className="py-2 text-xs text-gray-500">No IOCs have been added to this investigation yet.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function InvestigationBucket({ title, count, text }: { title: string; count: number; text: string }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
      <div className="flex items-start justify-between gap-2">
        <b className="text-xs text-gray-200">{title}</b>
        <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{count}</span>
      </div>
      <p className="mt-2 text-[10px] leading-4 text-gray-500">{text}</p>
    </div>
  );
}

function uniqueIocNodes(nodes: Array<Record<string, unknown>>) {
  const merged = new Map<string, { key: string; value: string; type: string; source: string; description: string; sourceRefs: string[] }>();
  nodes
    .map(node => {
      const rawValue = String(node.value ?? node.indicator ?? node.observable ?? node.label ?? '');
      const value = rawValue.trim();
      const type = String(node.ioc_type ?? node.indicator_type ?? node.type ?? 'ioc');
      const source = String(node.source ?? node.provider ?? node.evidence_source ?? '');
      const description = String(node.description ?? node.summary ?? '');
      const sourceRefs = collectNodeSourceRefs(node);
      return { key: `${type}:${value}`, value, type, source, description, sourceRefs };
    })
    .forEach(node => {
      if (!node.value) return false;
      const normalized = node.key.toLowerCase();
      const existing = merged.get(normalized);
      if (!existing) {
        merged.set(normalized, node);
        return true;
      }
      merged.set(normalized, {
        ...existing,
        sourceRefs: mergeArrays(existing.sourceRefs, node.sourceRefs),
        source: existing.source || node.source,
        description: existing.description || node.description,
      });
      return true;
    });
  return Array.from(merged.values()).slice(0, 100);
}

function uniqueSuspiciousBehaviorNodes(nodes: Array<Record<string, unknown>>) {
  const directNodes = nodes.filter(node => String(node.type ?? '') === 'suspicious-behavior');
  const nestedNodes = nodes.flatMap(node => {
    const nested = node.expected_suspicious_behaviors;
    return Array.isArray(nested) ? nested.filter(item => item && typeof item === 'object') as Array<Record<string, unknown>> : [];
  });
  const seen = new Set<string>();
  return [...directNodes, ...nestedNodes]
    .map(node => {
      const evidence = String(node.evidence ?? node.label ?? '');
      const why = String(node.why ?? node.reason ?? '');
      const refs = stringArray(node.refs);
      const ttps = stringArray(node.ttps);
      const iocs = stringArray(node.iocs);
      const found = node.found !== false;
      const sourceRefs = collectNodeSourceRefs(node);
      return {
        key: `${sourceRefs.join('|')}:${evidence}:${why}`.toLowerCase(),
        evidence,
        why,
        refs,
        ttps,
        iocs,
        found,
        sourceRefs,
      };
    })
    .filter(node => {
      if (!node.found || !node.evidence) return false;
      if (seen.has(node.key)) return false;
      seen.add(node.key);
      return true;
    })
    .slice(0, 60);
}

function uniqueTtpEvidenceNodes(nodes: Array<Record<string, unknown>>) {
  const seen = new Set<string>();
  return nodes
    .filter(node => String(node.type ?? '') === 'ttp-evidence')
    .map(node => {
      const attackId = String(node.attack_id ?? node.id ?? '').toUpperCase();
      const label = String(node.label ?? attackId);
      const sourceRef = collectNodeSourceRefs(node)[0] ?? String(node.source ?? 'analysis');
      return {
        key: `${sourceRef}:${attackId}`,
        attackId,
        label,
        sourceRef,
      };
    })
    .filter(node => {
      if (!node.attackId) return false;
      const key = node.key.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 250);
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map(item => String(item)).filter(Boolean);
}

function collectNodeSourceRefs(node: Record<string, unknown>) {
  return mergeArrays([
    ...stringArray(node.source_refs),
    ...stringArray(node.references),
    ...stringArray(node.refs),
    String(node.source_ref ?? '').trim(),
    String(node.analysis_id ?? '').trim(),
    String(node.source ?? '').trim(),
  ].filter(Boolean), []);
}

function mergeArrays(a: string[], b: string[]) {
  return Array.from(new Set([...a, ...b].filter(Boolean)));
}

function buildReportContext({
  domain,
  rows,
  matches,
  relevantIocs,
  sections,
  investigation,
}: {
  domain: string;
  rows: ReportRow[];
  matches: Array<{ group_attack_id: string; group_name: string; similarity: number; shared_count: number; shared_techniques: string[] }>;
  relevantIocs: IOCItem[];
  sections: ReportSections;
  investigation: Investigation | null;
}) {
  const lines = [
    `Domain: ${domain}`,
    `Included sections: ${Object.entries(sections).filter(([, enabled]) => enabled).map(([name]) => name).join(', ')}`,
    `Navigator summary: ${rows.length} selected TTPs, ${rows.filter(row => row.covered).length} covered, ${rows.filter(row => !row.covered).length} coverage gaps.`,
    '',
  ];
  if (sections.ttps) {
    lines.push('TTP evidence:');
    rows.slice(0, 45).forEach(row => {
      lines.push([
        `${row.id} ${row.name}`,
        `coverage=${row.covered ? 'covered' : 'gap'}`,
        `mapping=${row.assessment.mapping ?? 'weak'}`,
        `confidence=${row.assessment.confidence ?? 'low'}`,
        `maturity=${row.assessment.maturity ?? 'none'}`,
        row.assessment.evidence ? `evidence=${truncate(row.assessment.evidence, 120)}` : '',
        row.assessment.source ? `source=${truncate(row.assessment.source, 80)}` : '',
      ].filter(Boolean).join(' | '));
    });
    if (rows.length > 45) lines.push(`Additional TTPs omitted from AI context: ${rows.length - 45}.`);
    lines.push('');
  }
  if (sections.actors) {
    lines.push('Threat actor comparison:');
    matches.slice(0, 8).forEach((item, index) => {
      lines.push(`${index + 1}. ${item.group_name} (${item.group_attack_id}) | similarity=${Math.round(item.similarity * 100)}% | shared=${item.shared_count} | shared_ttps=${item.shared_techniques.slice(0, 18).join(', ')}`);
    });
    lines.push('');
  }
  if (sections.iocs) {
    lines.push('Relevant IOC enrichment:');
    relevantIocs.slice(0, 25).forEach(item => {
      lines.push(`${item.value} (${item.type}) | source=${item.source || 'unknown'} | malware=${item.malware_family || 'unknown'} | campaign=${item.campaign || 'unknown'} | ttps=${item.technique_ids?.slice(0, 8).join(', ') || 'none'} | confidence=${item.confidence ?? 0}`);
    });
    if (relevantIocs.length > 25) lines.push(`Additional IOCs omitted from AI context: ${relevantIocs.length - 25}.`);
  }
  if (investigation) {
    lines.push('', 'Investigation workspace evidence:');
    lines.push(`Name: ${investigation.name}`);
    lines.push(`TTP layer: ${investigation.technique_ids.join(', ')}`);
    lines.push(`Actor leads: ${investigation.actor_ids.join(', ') || 'none'}`);
    lines.push(`Report/log/IOC evidence nodes: ${investigation.evidence_nodes.length}`);
    investigation.evidence_nodes.slice(-30).forEach(node => {
      lines.push(`${String(node.type ?? 'evidence')} | ${String(node.label ?? node.value ?? node.id ?? '')} | ${String(node.summary ?? node.description ?? '').slice(0, 180)}`);
    });
    lines.push('Timeline:');
    investigation.timeline.slice(-20).forEach(item => lines.push(`${String(item.at ?? '')} | ${String(item.event ?? item.source ?? '')}`));
  }
  return truncate(lines.join('\n'), 7600);
}

function truncate(value: string, limit: number) {
  return value.length > limit ? `${value.slice(0, Math.max(0, limit - 3))}...` : value;
}

async function readSseText(response: Response) {
  if (!response.ok || !response.body) {
    throw new Error(await response.text() || `HTTP ${response.status}`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let output = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const raw = line.slice(6);
      try {
        const event = JSON.parse(raw);
        if (event.type === 'token') output += event.content ?? '';
        if (event.type === 'error') throw new Error(event.message ?? 'AI generation failed');
      } catch (error) {
        if (error instanceof SyntaxError) continue;
        throw error;
      }
    }
  }
  return output;
}

function downloadBlob(content: BlobPart, filename: string, type: string) {
  const url = URL.createObjectURL(content instanceof Blob ? content : new Blob([content], { type }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function markdownToPlainText(markdown: string) {
  return markdown
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/\*\*(.*?)\*\*/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\[(.*?)\]\((.*?)\)/g, '$1 ($2)');
}

function buildSimplePdf(text: string) {
  const escapedLines = wrapText(text, 92).flatMap(line => line === '' ? [' '] : [line]);
  const pages: string[][] = [];
  for (let i = 0; i < escapedLines.length; i += 46) pages.push(escapedLines.slice(i, i + 46));
  if (!pages.length) pages.push(['No report content.']);

  const objects: string[] = [];
  objects.push('<< /Type /Catalog /Pages 2 0 R >>');
  objects.push(`<< /Type /Pages /Kids [${pages.map((_, index) => `${3 + index * 2} 0 R`).join(' ')}] /Count ${pages.length} >>`);
  pages.forEach((page, index) => {
    const pageObj = 3 + index * 2;
    const contentObj = pageObj + 1;
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Contents ${contentObj} 0 R >>`);
    const stream = [
      'BT',
      '/F1 10 Tf',
      '50 750 Td',
      ...page.map((line, lineIndex) => `${lineIndex === 0 ? '' : '0 -14 Td'}(${escapePdf(line)}) Tj`),
      'ET',
    ].join('\n');
    objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
  });

  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [0];
  objects.forEach((object, index) => {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach(offset => {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return new Blob([pdf], { type: 'application/pdf' });
}

function wrapText(text: string, width: number) {
  return text.split('\n').flatMap(line => {
    if (line.length <= width) return [line];
    const words = line.split(/\s+/);
    const lines: string[] = [];
    let current = '';
    words.forEach(word => {
      if ((current + ' ' + word).trim().length > width) {
        lines.push(current);
        current = word;
      } else {
        current = `${current} ${word}`.trim();
      }
    });
    if (current) lines.push(current);
    return lines;
  });
}

function escapePdf(text: string) {
  return text.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'adversarygraph-report';
}

function FlowStep({
  number,
  title,
  text,
  actionLabel,
  onAction,
  disabled = false,
}: {
  number: number;
  title: string;
  text: string;
  actionLabel?: string;
  onAction?: () => void;
  disabled?: boolean;
}) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
      <div className="flex items-start gap-3">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded bg-mitre-accent text-xs font-bold text-white">{number}</span>
        <div className="min-w-0">
          <b className="block text-sm text-gray-200">{title}</b>
          <p className="mt-1 text-xs leading-5 text-gray-500">{text}</p>
          {actionLabel && onAction && (
            <button type="button" onClick={onAction} disabled={disabled} className="secondary-action mt-3 text-xs disabled:opacity-40">
              {actionLabel}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function mergeInvestigation(
  row: Investigation,
  patch: Partial<Pick<Investigation, 'actor_ids' | 'technique_ids' | 'report_ids' | 'evidence_nodes' | 'evidence_edges' | 'timeline'>>,
): Omit<Investigation, 'id' | 'created_at' | 'updated_at'> {
  return {
    name: row.name,
    description: row.description,
    status: row.status || 'active',
    domain: row.domain,
    actor_ids: mergeStrings(row.actor_ids, patch.actor_ids),
    technique_ids: mergeStrings(row.technique_ids, patch.technique_ids?.map(item => item.toUpperCase())),
    report_ids: mergeStrings(row.report_ids, patch.report_ids),
    evidence_nodes: mergeObjects(row.evidence_nodes, patch.evidence_nodes),
    evidence_edges: mergeObjects(row.evidence_edges, patch.evidence_edges),
    timeline: [...(row.timeline ?? []), ...(patch.timeline ?? [])].slice(-250),
  };
}

function mergeStrings(current: string[] = [], incoming: string[] = []) {
  return Array.from(new Set([...current, ...incoming].filter(Boolean))).sort();
}

function mergeObjects(current: Array<Record<string, unknown>> = [], incoming: Array<Record<string, unknown>> = []) {
  const seen = new Set<string>();
  return [...current, ...incoming].filter(item => {
    const key = String(item.id ?? item.value ?? item.label ?? JSON.stringify(item));
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(-500);
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/50">
      <h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>
      {children}
    </section>
  );
}

function CheckRow({ checked, title, text, onChange }: { checked: boolean; title: string; text: string; onChange: () => void }) {
  return (
    <label className="flex cursor-pointer gap-3 rounded border border-gray-800 bg-gray-950/40 p-3 hover:border-gray-700">
      <input type="checkbox" checked={checked} onChange={onChange} className="mt-1 h-4 w-4 accent-mitre-accent" />
      <span>
        <span className="block text-sm font-semibold text-gray-200">{title}</span>
        <span className="mt-1 block text-xs leading-5 text-gray-500">{text}</span>
      </span>
    </label>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
      <b className="block text-lg text-white">{value}</b>
      <span className="text-[10px] text-gray-500">{label}</span>
    </div>
  );
}
