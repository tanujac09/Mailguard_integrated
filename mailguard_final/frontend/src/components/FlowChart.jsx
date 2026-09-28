import React, { useState } from 'react'

const STATUS_META = {
  green: { color: '#1f9d55', label: 'No issue found', icon: '✓' },
  amber: { color: '#d97706', label: 'Needs review', icon: '!' },
  red: { color: '#dc2626', label: 'Problem detected', icon: '✕' },
}

function prettyKey(key) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

function DetailValue({ value }) {
  if (value === null || value === undefined || value === '') {
    return <span className="muted">—</span>
  }
  if (typeof value === 'boolean') {
    return <span>{value ? 'Yes' : 'No'}</span>
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="muted">none</span>
    if (typeof value[0] === 'object' && value[0] !== null) {
      // array of objects -> mini table
      const cols = Object.keys(value[0])
      return (
        <table className="mini-table">
          <thead>
            <tr>
              {cols.map((c) => (
                <th key={c}>{prettyKey(c)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {value.map((row, i) => (
              <tr key={i}>
                {cols.map((c) => (
                  <td key={c}>
                    <DetailValue value={row[c]} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      )
    }
    return (
      <ul className="chip-list">
        {value.map((v, i) => (
          <li key={i}>{String(v)}</li>
        ))}
      </ul>
    )
  }
  if (typeof value === 'object') {
    return (
      <table className="mini-table">
        <tbody>
          {Object.entries(value).map(([k, v]) => (
            <tr key={k}>
              <td className="mini-key">{prettyKey(k)}</td>
              <td>
                <DetailValue value={v} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return <span>{String(value)}</span>
}

export default function FlowChart({ steps }) {
  const [selected, setSelected] = useState(steps && steps.length ? 0 : null)
  if (!steps || steps.length === 0) return null

  const step = selected !== null ? steps[selected] : null
  const manualSteps = step?.details?.manual_steps_this_replaces
  const findings = step?.details?.findings
  const flagSummary = step?.step_key === 'content' ? step?.details?.flag_summary : null

  return (
    <div className="flowchart-wrap">
      <h2>What an analyst would manually check (click a step)</h2>
      <div className="flowchart-row">
        {steps.map((s, i) => {
          const meta = STATUS_META[s.status] || STATUS_META.amber
          return (
            <React.Fragment key={s.step_key}>
              <button
                className={`flow-box ${selected === i ? 'flow-box-active' : ''}`}
                style={{ borderColor: meta.color }}
                onClick={() => setSelected(i)}
              >
                <span className="flow-box-icon" style={{ backgroundColor: meta.color }}>
                  {meta.icon}
                </span>
                <span className="flow-box-title">{s.title}</span>
                <span className="flow-box-status" style={{ color: meta.color }}>
                  {meta.label}
                </span>
              </button>
              {i < steps.length - 1 && <div className="flow-arrow">→</div>}
            </React.Fragment>
          )
        })}
      </div>

      {step && (
        <div className="flow-detail-panel" style={{ borderColor: (STATUS_META[step.status] || STATUS_META.amber).color }}>
          <div className="flow-detail-header">
            <h3>{step.title}</h3>
            <span
              className="risk-badge"
              style={{ backgroundColor: (STATUS_META[step.status] || STATUS_META.amber).color }}
            >
              {(STATUS_META[step.status] || STATUS_META.amber).label}
            </span>
          </div>
          <p className="flow-summary">{step.summary}</p>

          {flagSummary && (
            <div className="nlp-flag-summary">
              <h4>Why this was flagged</h4>
              <p>{flagSummary}</p>
            </div>
          )}

          {findings && findings.length > 0 && (
            <>
              <h4>Findings</h4>
              <ul className="chip-list">
                {findings.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            </>
          )}

          <h4>Full evidence</h4>
          <DetailValue
            value={Object.fromEntries(
              Object.entries(step.details || {}).filter(
                ([k]) => k !== 'findings' && k !== 'manual_steps_this_replaces'
              )
            )}
          />

          {manualSteps && manualSteps.length > 0 && (
            <>
              <h4>Manual process this step replaces</h4>
              <ol className="manual-steps-list">
                {manualSteps.map((m, i) => (
                  <li key={i}>{m}</li>
                ))}
              </ol>
            </>
          )}
        </div>
      )}
    </div>
  )
}
