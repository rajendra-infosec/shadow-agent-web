import { useRef, useState, type ChangeEvent, type DragEvent } from 'react';
import { PARSER_LIMITS, parseMakeBlueprint } from './adapters/makeAdapter';
import { analyzeWorkflow, type ScanReport } from './engine/taintEngine';
import { SAMPLE_BLUEPRINTS, type SampleBlueprint } from './samples/blueprints';

function parseGatewayHosts(raw: string): string[] {
  return raw
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
}

export default function App() {
  const [rawJson, setRawJson] = useState<string>('');
  const [gatewayInput, setGatewayInput] = useState<string>('');
  const [activeSampleId, setActiveSampleId] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const executeScan = (jsonText: string, gatewaysText: string) => {
    const trimmed = jsonText.trim();
    if (!trimmed) {
      setError('Paste a Make.com blueprint JSON or load one of the samples above.');
      setReport(null);
      return;
    }

    try {
      const ir = parseMakeBlueprint(trimmed, {
        allowedGatewayHosts: parseGatewayHosts(gatewaysText),
      });
      const result = analyzeWorkflow(ir);
      setReport(result);
      setError(null);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to parse blueprint JSON.';
      setError(message);
      setReport(null);
    }
  };

  const handleLoadSample = (sample: SampleBlueprint) => {
    setActiveSampleId(sample.id);
    setRawJson(sample.json);
    executeScan(sample.json, gatewayInput);
  };

  const handleFile = (file: File) => {
    if (file.size > PARSER_LIMITS.MAX_INPUT_BYTES) {
      setError(
        `File exceeds the ${PARSER_LIMITS.MAX_INPUT_BYTES / (1024 * 1024)} MB client-side safety limit.`
      );
      setReport(null);
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const content = typeof reader.result === 'string' ? reader.result : '';
      setActiveSampleId(null);
      setRawJson(content);
      executeScan(content, gatewayInput);
    };
    reader.onerror = () => {
      setError('Could not read the selected file.');
    };
    reader.readAsText(file);
  };

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
    e.target.value = '';
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  const handleClear = () => {
    setRawJson('');
    setActiveSampleId(null);
    setReport(null);
    setError(null);
  };

  const handleExportReport = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `shadow-agent-report-${report.workflowName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <h1>Shadow Agent</h1>
          <p>Client-Side Make.com Blueprint Taint & AI Gateway Scanner</p>
        </div>
        <div className="csp-pill" title="Enforced in production via HTTP Content-Security-Policy header">
          <span className="csp-dot" aria-hidden="true" />
          CSP: connect-src 'none' • Zero Upload
        </div>
      </header>

      <section aria-label="One-click demo blueprints">
        <div className="section-label">1-Click Demo Blueprints</div>
        <div className="samples-grid">
          {SAMPLE_BLUEPRINTS.map((sample) => (
            <button
              key={sample.id}
              type="button"
              className={`sample-btn ${activeSampleId === sample.id ? 'active' : ''}`}
              onClick={() => handleLoadSample(sample)}
            >
              <div className="sample-top">
                <span>{sample.label}</span>
                <span className={`badge badge-${sample.badge}`}>{sample.badge}</span>
              </div>
              <div className="sample-desc">{sample.description}</div>
            </button>
          ))}
        </div>
      </section>

      <section className="input-card" aria-label="Blueprint input">
        <div
          className={`dropzone ${isDragging ? 'dragging' : ''}`}
          role="button"
          tabIndex={0}
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
          }}
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
        >
          <strong>Drop a Make.com blueprint (.json) or click to browse</strong>
          <span>Parsed 100% locally in browser memory — max 5 MB</span>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            style={{ display: 'none' }}
            onChange={handleFileChange}
          />
        </div>

        <div className="controls-row">
          <input
            type="text"
            className="gateway-input"
            placeholder="Optional corporate AI Gateway hosts (comma-separated, e.g. ai-gw.corp.internal)"
            value={gatewayInput}
            onChange={(e) => setGatewayInput(e.target.value)}
            aria-label="Custom corporate AI Gateway hostnames"
          />
        </div>

        <textarea
          className="json-textarea"
          placeholder="Or paste raw Make.com blueprint JSON here..."
          value={rawJson}
          onChange={(e) => {
            setActiveSampleId(null);
            setRawJson(e.target.value);
          }}
          spellCheck={false}
          aria-label="Make.com blueprint JSON"
        />

        <div className="action-bar">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => executeScan(rawJson, gatewayInput)}
          >
            Scan Blueprint
          </button>
          <button type="button" className="btn" onClick={handleClear}>
            Clear
          </button>
          {report && (
            <button type="button" className="btn" onClick={handleExportReport}>
              Export JSON Report
            </button>
          )}
        </div>
      </section>

      {error && (
        <div className="error-box" role="alert">
          <strong>Scan Error:</strong> {error}
        </div>
      )}

      {report && (
        <section aria-label="Security scan report">
          <div className="report-header">
            <div className="report-title-row">
              <h2>{report.workflowName}</h2>
              <span className={`badge badge-${report.summary.verdict}`}>
                {report.summary.verdict} • RISK {report.summary.riskScore}/100
              </span>
            </div>

            <div className="stats-grid">
              <div className="stat-tile">
                <div className="stat-value">{report.summary.totalNodes}</div>
                <div className="stat-label">Modules Parsed</div>
              </div>
              <div className="stat-tile">
                <div className="stat-value">{report.summary.criticalCount}</div>
                <div className="stat-label">Critical</div>
              </div>
              <div className="stat-tile">
                <div className="stat-value">{report.summary.highCount}</div>
                <div className="stat-label">High</div>
              </div>
              <div className="stat-tile">
                <div className="stat-value">{report.summary.gatewayBypassCount}</div>
                <div className="stat-label">Gateway Bypasses</div>
              </div>
              <div className="stat-tile">
                <div className="stat-value">{report.summary.gatewayRoutedCount}</div>
                <div className="stat-label">Gateway Routed</div>
              </div>
            </div>
          </div>

          {report.findings.length === 0 ? (
            <div className="clean-banner">
              <strong>No Lethal Trifecta or AI Gateway bypasses detected.</strong> All inspected
              LLM nodes and outbound sinks follow isolated or gateway-routed patterns.
            </div>
          ) : (
            <div className="findings-list">
              {report.findings.map((finding) => (
                <article key={finding.id} className="finding-card">
                  <div className="finding-top">
                    <span className={`badge badge-${finding.severity}`}>{finding.severity}</span>
                    <span className="finding-rule">{finding.ruleId}</span>
                    <span className="finding-rule">
                      • {finding.confidence.toUpperCase()}
                    </span>
                    {finding.mitigatedByGateway && (
                      <span className="badge badge-CLEAN">GATEWAY ROUTED</span>
                    )}
                  </div>

                  <h3 className="finding-title">{finding.title}</h3>

                  {finding.pathLabels.length > 0 && (
                    <div className="taint-path" aria-label="Taint path">
                      {finding.pathLabels.map((label, idx) => (
                        <span key={`${finding.id}-${idx}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                          <span className="path-node">{label}</span>
                          {idx < finding.pathLabels.length - 1 && (
                            <span className="path-arrow" aria-hidden="true">
                              →
                            </span>
                          )}
                        </span>
                      ))}
                    </div>
                  )}

                  <p className="finding-desc">{finding.description}</p>

                  <div className="finding-fix">
                    <strong>Remediation:</strong> {finding.remediation}
                  </div>
                </article>
              ))}
            </div>
          )}

          {report.parseWarnings.length > 0 && (
            <div className="warnings-box">
              <strong>Parser Warnings ({report.parseWarnings.length})</strong>
              <ul>
                {report.parseWarnings.map((warning, idx) => (
                  <li key={idx}>{warning}</li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      <footer className="footer-note">
        <span>Open-Source Static Taint Analyzer for Make.com Blueprints</span>
        <span>Zero telemetry • Verify in DevTools Network tab</span>
      </footer>
    </main>
  );
}