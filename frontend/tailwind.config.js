/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        siem: {
          bg:      'var(--siem-bg)',
          surface: 'var(--siem-surface)',
          border:  'var(--siem-border)',
          text:    'var(--siem-text)',
          muted:   'var(--siem-muted)',
          accent:  'var(--siem-accent)',
          green:   'var(--siem-green)',
          yellow:  'var(--siem-yellow)',
          orange:  'var(--siem-orange)',
          red:     'var(--siem-red)',
        }
      }
    }
  },
  plugins: []
}
