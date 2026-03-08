import { useEffect, useState } from 'react'
import { Settings as SettingsIcon, Mail, CheckCircle, AlertCircle, Send } from 'lucide-react'
import api from '../api/client'

export default function Settings() {
  const [smtp, setSmtp] = useState(null)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)

  useEffect(() => {
    api.get('/api/v1/settings/smtp').then(r => setSmtp(r.data)).catch(() => {})
  }, [])

  const testSMTP = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      await api.post('/api/v1/settings/smtp/test')
      setTestResult({ ok: true, msg: 'Test email sent successfully! Check your inbox.' })
    } catch (err) {
      setTestResult({ ok: false, msg: err.response?.data?.error || 'Test failed' })
    } finally { setTesting(false) }
  }

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div className="flex items-center gap-2">
        <SettingsIcon className="text-siem-accent" size={20} />
        <h1 className="text-xl font-bold text-siem-text">Settings</h1>
      </div>

      {/* SMTP */}
      <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 px-5 py-4 border-b border-siem-border">
          <Mail className="text-siem-accent" size={16} />
          <span className="text-sm font-semibold text-siem-text">Email Alerts (SMTP)</span>
          {smtp && (
            <span className={`ml-auto text-xs px-2 py-0.5 rounded-full border ${
              smtp.enabled ? 'bg-siem-green/10 border-siem-green/30 text-siem-green' : 'bg-siem-border/30 border-siem-border text-siem-muted'
            }`}>
              {smtp.enabled ? 'Enabled' : 'Disabled'}
            </span>
          )}
        </div>

        <div className="p-5 space-y-4">
          <p className="text-sm text-siem-muted">
            SMTP settings are configured in <code className="text-siem-accent bg-siem-bg px-1.5 py-0.5 rounded text-xs">server.yaml</code> on the server.
            Restart the API container after changes.
          </p>

          {smtp ? (
            <div className="bg-siem-bg border border-siem-border rounded-xl overflow-hidden">
              {[
                ['Host',         smtp.host || '—'],
                ['Port',         smtp.port],
                ['Username',     smtp.username || '—'],
                ['From',         smtp.from || '—'],
                ['Recipients',   smtp.to?.join(', ') || '—'],
                ['Min Severity', `${smtp.min_severity} — ${['','Info','Low','Medium','High','Critical'][smtp.min_severity] || smtp.min_severity}`],
                ['TLS',          smtp.use_tls ? 'Enabled' : 'Disabled'],
              ].map(([label, value], i) => (
                <div key={label} className={`flex gap-3 px-4 py-2.5 text-sm ${i % 2 === 0 ? '' : 'bg-white/[0.02]'}`}>
                  <span className="text-siem-muted w-32 shrink-0">{label}</span>
                  <span className="text-siem-text text-xs font-mono">{String(value)}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-siem-muted text-sm">Loading...</div>
          )}

          {smtp?.enabled && (
            <div className="space-y-3">
              <button onClick={testSMTP} disabled={testing}
                className="flex items-center gap-2 text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-4 py-2 rounded-lg disabled:opacity-50 transition-colors">
                <Send size={13} />
                {testing ? 'Sending...' : 'Send test email'}
              </button>
              {testResult && (
                <div className={`flex items-center gap-2 text-xs px-3 py-2 rounded-lg border ${
                  testResult.ok
                    ? 'bg-siem-green/10 border-siem-green/30 text-siem-green'
                    : 'bg-red-900/20 border-red-700/30 text-red-400'
                }`}>
                  {testResult.ok ? <CheckCircle size={13} /> : <AlertCircle size={13} />}
                  {testResult.msg}
                </div>
              )}
            </div>
          )}

          {smtp && !smtp.enabled && (
            <div className="text-xs text-siem-muted bg-siem-bg border border-siem-border rounded-lg p-3">
              To enable email alerts, edit <code className="text-siem-accent">server.yaml</code>:
              <pre className="mt-2 text-siem-accent/80">{`smtp:
  enabled: true
  host: "smtp.gmail.com"
  port: 587
  username: "you@gmail.com"
  password: "your-app-password"
  from: "ObsidianWatch <you@gmail.com>"
  to:
    - "soc@yourcompany.com"
  min_severity: 4
  use_tls: true`}</pre>
              Then restart: <code className="text-siem-accent">sudo docker compose restart mgmt-api</code>
            </div>
          )}
        </div>
      </div>

      {/* About */}
      <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
        <div className="text-sm font-semibold text-siem-text mb-3">About ObsidianWatch</div>
        <div className="space-y-1 text-xs text-siem-muted">
          <div>Management Platform <span className="text-siem-accent">v0.3.0</span></div>
          <div>Agent <span className="text-siem-accent">v0.2.0</span></div>
          <div>License <span className="text-siem-accent">MIT</span></div>
          <div className="pt-2">
            <a href="https://github.com/honbles/obsidianwatch" target="_blank" rel="noopener noreferrer"
              className="text-siem-accent hover:underline">github.com/honbles/obsidianwatch</a>
          </div>
        </div>
      </div>
    </div>
  )
}
