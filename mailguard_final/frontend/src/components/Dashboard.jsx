import React, { useEffect, useState, useRef } from 'react'
import { Link } from 'react-router-dom'
import { listEmails, uploadEmail } from '../api.js'
import RiskBadge from './RiskBadge.jsx'

export default function Dashboard() {
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [uploading, setUploading] = useState(false)
  const [showAll, setShowAll] = useState(false)
  const fileInput = useRef(null)

  async function refresh() {
    setLoading(true)
    setError('')
    try {
      const data = await listEmails(!showAll)
      setEmails(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showAll])

  async function handleFile(e) {
    const file = e.target.files[0]
    if (!file) return
    setUploading(true)
    setError('')
    try {
      await uploadEmail(file)
      await refresh()
    } catch (err) {
      setError(err.message)
    } finally {
      setUploading(false)
      if (fileInput.current) fileInput.current.value = ''
    }
  }

  return (
    <div className="dashboard">
      <div className="dashboard-toolbar">
        <div>
          <h1>Analyst Inbox</h1>
          <p className="subtle">
            {showAll ? 'Showing all ingested emails.' : 'Showing emails flagged as suspicious or fraudulent.'}
          </p>
        </div>
        <div className="toolbar-actions">
          <label className="toggle">
            <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
            Show all (incl. clean)
          </label>
      
          <label className="upload-btn">
            {uploading ? 'Analyzing…' : '⬆ Upload .eml'}
            <input
              type="file"
              accept=".eml,.msg,.txt"
              ref={fileInput}
              onChange={handleFile}
              disabled={uploading}
              hidden
            />
          </label>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}
      {loading ? (
        <p className="subtle">Loading…</p>
      ) : emails.length === 0 ? (
        <div className="empty-state">
          <p>No emails here yet.</p>
          <p className="subtle">Upload a .eml file (try the samples in backend/sample_emails/) to see it analyzed.</p>
        </div>
      ) : (
        <table className="email-table">
          <thead>
            <tr>
              <th>Verdict</th>
              <th>Subject</th>
              <th>From</th>
              <th>Origin</th>
              <th>Received</th>
            </tr>
          </thead>
          <tbody>
            {emails.map((email) => (
              <tr key={email.id}>
                <td>
                  <Link to={`/emails/${email.id}`}>
                    <RiskBadge verdict={email.verdict} score={email.fraud_score} />
                  </Link>
                </td>
                <td>
                  <Link to={`/emails/${email.id}`} className="subject-link">
                    {email.subject || '(no subject)'}
                  </Link>
                </td>
                <td className="muted">{email.sender || '—'}</td>
                <td className="muted">{email.origin_country || '—'}</td>
                <td className="muted">{new Date(email.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
