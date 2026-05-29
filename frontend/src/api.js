// Thin API client for the WinDiag Pro backend.
const BASE = '/api'

async function get(path) {
  const res = await fetch(BASE + path)
  if (!res.ok) throw new Error(`${path} 请求失败: ${res.status}`)
  return res.json()
}

async function postBlob(path, body, filename) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {})
  })
  if (!res.ok) throw new Error(`${path} 导出失败: ${res.status}`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export const api = {
  health: () => get('/health'),
  quick: () => get('/quick'),
  securityScan: () => get('/security/scan'),
  securityLast: () => get('/security/last'),
  diagScan: () => get('/diag/scan'),
  diagLast: () => get('/diag/last'),
  checklist: () => get('/checklist'),
  exportHTML: (meta) => postBlob('/report/html', meta, 'windiag-report.html'),
  exportJSON: (meta) => postBlob('/report/json', meta, 'windiag-report.json'),
  exportCSV: (meta) => postBlob('/report/csv', meta, 'windiag-report.csv')
}
