import { useState } from 'react'
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
              <svg width="56" height="56" viewBox="0 0 220 220" xmlns="http://www.w3.org/2000/svg" className="mx-auto">
                <defs>
                  <radialGradient id="lg-glow" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.35"/>
                    <stop offset="100%" stopColor="#00d4ff" stopOpacity="0"/>
                  </radialGradient>
                  <radialGradient id="lg-lens" cx="38%" cy="35%" r="60%">
                    <stop offset="0%" stopColor="#1a3a4a"/>
                    <stop offset="60%" stopColor="#0a1a22"/>
                    <stop offset="100%" stopColor="#040e14"/>
                  </radialGradient>
                  <radialGradient id="lg-iris" cx="40%" cy="38%" r="55%">
                    <stop offset="0%" stopColor="#1e5a6e"/>
                    <stop offset="50%" stopColor="#0d3040"/>
                    <stop offset="100%" stopColor="#061820"/>
                  </radialGradient>
                  <radialGradient id="lg-pupil" cx="42%" cy="40%" r="55%">
                    <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.9"/>
                    <stop offset="40%" stopColor="#0088aa"/>
                    <stop offset="100%" stopColor="#003344"/>
                  </radialGradient>
                </defs>
                <circle cx="110" cy="110" r="95" fill="url(#lg-glow)"/>
                <polygon points="110,12 193,59 193,161 110,208 27,161 27,59" fill="#06111a" stroke="#1a3a4a" strokeWidth="1.5"/>
                <polygon points="110,22 183,65 183,155 110,198 37,155 37,65" fill="none" stroke="#00d4ff" strokeWidth="0.5" strokeOpacity="0.3"/>
                <circle cx="110" cy="108" r="62" fill="url(#lg-lens)"/>
                <circle cx="110" cy="108" r="62" fill="none" stroke="#00d4ff" strokeWidth="1.2" strokeOpacity="0.6"/>
                <circle cx="110" cy="108" r="42" fill="url(#lg-iris)"/>
                <circle cx="110" cy="108" r="42" fill="none" stroke="#00d4ff" strokeWidth="0.8" strokeOpacity="0.5"/>
                <circle cx="110" cy="108" r="36" fill="none" stroke="#00d4ff" strokeWidth="0.4" strokeOpacity="0.2" strokeDasharray="3 4"/>
                <circle cx="110" cy="108" r="22" fill="url(#lg-pupil)"/>
                <circle cx="110" cy="108" r="22" fill="none" stroke="#00d4ff" strokeWidth="1" strokeOpacity="0.8"/>
                <circle cx="110" cy="108" r="10" fill="#001822"/>
                <circle cx="110" cy="108" r="10" fill="none" stroke="#00d4ff" strokeWidth="1.5" strokeOpacity="0.9"/>
                <ellipse cx="96" cy="92" rx="9" ry="6" fill="white" fillOpacity="0.1" transform="rotate(-30 96 92)"/>
              </svg>
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
