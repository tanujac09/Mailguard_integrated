const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function getToken() {
  return localStorage.getItem('mailguard_token')
}

export function setToken(token) {
  localStorage.setItem('mailguard_token', token)
}

export function clearToken() {
  localStorage.removeItem('mailguard_token')
}

export function isLoggedIn() {
  return !!getToken()
}

async function request(path, options = {}) {
  const headers = options.headers || {}
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(`${API_URL}${path}`, { ...options, headers })

  if (res.status === 401) {
    clearToken()
    window.location.href = '/login'
    throw new Error('Session expired, please log in again.')
  }

  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail || detail
    } catch (_) {}
    throw new Error(detail)
  }

  if (res.status === 204) return null
  return res.json()
}

export async function login(username, password) {
  const form = new URLSearchParams()
  form.append('username', username)
  form.append('password', password)

  const res = await fetch(`${API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
  })
  if (!res.ok) {
    let detail = 'Login failed'
    try {
      const body = await res.json()
      detail = body.detail || detail
    } catch (_) {}
    throw new Error(detail)
  }
  const data = await res.json()
  setToken(data.access_token)
  return data
}

export function listEmails(flaggedOnly = true) {
  return request(`/emails?flagged_only=${flaggedOnly}`)
}

export function getEmail(id) {
  return request(`/emails/${id}`)
}

export function uploadEmail(file) {
  const formData = new FormData()
  formData.append('file', file)
  const token = getToken()
  return fetch(`${API_URL}/emails/upload`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: formData,
  }).then(async (res) => {
    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      throw new Error(body.detail || 'Upload failed')
    }
    return res.json()
  })
}

export function deleteEmail(id) {
  return request(`/emails/${id}`, { method: 'DELETE' })
}
