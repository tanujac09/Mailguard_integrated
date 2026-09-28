import React, { useEffect, useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { getEmail, deleteEmail } from '../api.js'
import RiskBadge from './RiskBadge.jsx'
import OriginMap from './OriginMap.jsx'
import FlowChart from './FlowChart.jsx'

export default function EmailDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [email, setEmail] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    getEmail(id)
      .then(setEmail)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [id])

  async function handleDelete() {
    if (!window.confirm('Remove this email from the case list? This cannot be undone.')) return
    await deleteEmail(id)
    navigate('/')
  }

  if (loading) return <p className="subtle">Loading…</p>
  if (error) return <div className="error-banner">{error}</div>
  if (!email) return null

  return (
    <div className="email-detail">
      <Link to="/" className="back-link">
        ← Back to inbox
      </Link>

      <div className="detail-header">
        <div>
          <h1>{email.subject || '(no subject)'}</h1>
          <p className="subtle">From {email.sender || 'unknown'} · {new Date(email.created_at).toLocaleString()}</p>
        </div>
        <div className="detail-header-actions">
          <RiskBadge verdict={email.verdict} score={email.fraud_score} />
          {email.sha256 && (
      <a
        href={`http://localhost:8501/?email_id=EML-${email.sha256.slice(0, 12)}`}
        target="_blank"
        rel="noopener noreferrer"
        className="part3-link"
      >
        🔗 View in Forensic Graph
      </a>
  )}
          <button className="danger-btn" onClick={handleDelete}>Delete case</button>
        </div>
      </div>

      <div className="detail-grid">
        <section className="card">
          <h2>Forensic Identity</h2>
          <table className="mini-table">
            <tbody>
              <tr><td className="mini-key">SHA-256</td><td className="mono">{email.sha256}</td></tr>
              <tr><td className="mini-key">From</td><td>{email.sender || '—'}</td></tr>
              <tr><td className="mini-key">Return-Path</td><td>{email.return_path || '—'}</td></tr>
              <tr><td className="mini-key">Reply-To</td><td>{email.reply_to || '—'}</td></tr>
              <tr><td className="mini-key">Date header</td><td>{email.date_header || '—'}</td></tr>
              <tr><td className="mini-key">Filename</td><td>{email.filename}</td></tr>
            </tbody>
          </table>
        </section>

        <section className="card">
          <h2>Origin Trace</h2>
          <table className="mini-table">
            <tbody>
              <tr><td className="mini-key">IP</td><td className="mono">{email.origin_ip || '—'}</td></tr>
              <tr><td className="mini-key">Location</td><td>{email.origin_city ? `${email.origin_city}, ${email.origin_country}` : (email.origin_country || '—')}</td></tr>
              <tr><td className="mini-key">ISP</td><td>{email.origin_isp || '—'}</td></tr>
              <tr><td className="mini-key">VPN/Proxy flag</td><td>{email.origin_is_proxy ? 'Yes' : 'No'}</td></tr>
            </tbody>
          </table>
          <OriginMap
            lat={email.origin_lat}
            lon={email.origin_lon}
            ip={email.origin_ip}
            city={email.origin_city}
            country={email.origin_country}
          />
        </section>
      </div>

      <section className="card">
        <h2>Body preview</h2>
        <pre className="body-preview">{email.body_preview || '(empty)'}</pre>
      </section>

      <section className="card">
        <FlowChart steps={email.steps} />
      </section>

      <section className="card">
        <h2>Raw headers (evidence)</h2>
        <pre className="raw-headers">{email.raw_headers}</pre>
      </section>
    </div>
  )
}
