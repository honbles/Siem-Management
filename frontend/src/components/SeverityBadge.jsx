export function SeverityBadge({ severity }) {
  const map = {
    5: { label: 'Critical', cls: 'bg-red-900 text-red-300 border border-red-700' },
    4: { label: 'High',     cls: 'bg-orange-900 text-orange-300 border border-orange-700' },
    3: { label: 'Medium',   cls: 'bg-yellow-900 text-yellow-300 border border-yellow-700' },
    2: { label: 'Low',      cls: 'bg-blue-900 text-blue-300 border border-blue-700' },
    1: { label: 'Info',     cls: 'bg-gray-800 text-gray-400 border border-gray-600' },
  }
  const { label, cls } = map[severity] || map[1]
  return (
    <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${cls}`}>
      {label}
    </span>
  )
}
