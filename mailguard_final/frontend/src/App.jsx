import React from 'react'
import { Routes, Route, Navigate, Link, useNavigate } from 'react-router-dom'
import Login from './components/Login.jsx'
import Dashboard from './components/Dashboard.jsx'
import EmailDetail from './components/EmailDetail.jsx'
import { isLoggedIn, clearToken } from './api.js'

function ProtectedRoute({ children }) {
  if (!isLoggedIn()) return <Navigate to="/login" replace />
  return children
}

function Header() {
  const navigate = useNavigate()
  if (!isLoggedIn()) return null
  return (
    <header className="app-header">
      <Link to="/" className="brand">🛡️ MailGuard <span>Analyst Console</span></Link>
      <button
        className="logout-btn"
        onClick={() => {
          clearToken()
          navigate('/login')
        }}
      >
        Log out
      </button>
    </header>
  )
}

export default function App() {
  return (
    <div className="app-shell">
      <Header />
      <main className="app-main">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/emails/:id"
            element={
              <ProtectedRoute>
                <EmailDetail />
              </ProtectedRoute>
            }
          />
        </Routes>
      </main>
    </div>
  )
}
