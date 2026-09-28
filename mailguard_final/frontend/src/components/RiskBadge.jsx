import React from 'react'

const COLORS = {
  Clean: '#1f9d55',
  Suspicious: '#d97706',
  Fraudulent: '#dc2626',
}

export default function RiskBadge({ verdict, score }) {
  const color = COLORS[verdict] || '#6b7280'
  return (
    <span className="risk-badge" style={{ backgroundColor: color }}>
      {verdict} · {Math.round(score)}
    </span>
  )
}
