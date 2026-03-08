import { useState } from 'react'
import logo from '../assets/logo.svg'
import { Shield } from 'lucide-react'
import api from '../api/client'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const { data } = await api.post('/auth/login', { username, password })
      localStorage.setItem('token', data.token)
      localStorage.setItem('user', JSON.stringify(data.user))
      onLogin(data.user, data.require_password_change)
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-siem-bg flex items-center justify-center">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="flex justify-center mb-3">
            <div className="bg-siem-accent/10 p-4 rounded-2xl">
              <Shield className="text-siem-accent" size={32} />
            </div>
          </div>
          <h1 className="text-2xl font-bold text-siem-text">ObsidianWatch</h1>
          <p className="text-siem-muted text-sm mt-1">Management Platform</p>
        </div>

        <div className="bg-siem-surface border border-siem-border rounded-2xl p-6 shadow-xl">
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs text-siem-muted mb-1.5">Username</label>
              <input
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2.5 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
                value={username} onChange={e => setUsername(e.target.value)} autoFocus
              />
            </div>
            <div>
              <label className="block text-xs text-siem-muted mb-1.5">Password</label>
              <input type="password"
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2.5 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
                value={password} onChange={e => setPassword(e.target.value)}
              />
            </div>
            {error && <div className="text-siem-red text-xs">{error}</div>}
            <button
              type="submit" disabled={loading}
              className="w-full bg-siem-accent hover:bg-siem-accent/90 text-white text-sm font-medium py-2.5 rounded-lg transition-colors disabled:opacity-50"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
