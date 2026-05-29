import { reactive } from 'vue'
import { api } from './api.js'

// Central reactive store shared across all views. A single security or
// diagnostics scan populates every page, mirroring the original SPA.
export const store = reactive({
  // live header gauge data
  quick: { cpu: 0, mem: 0, disk: 0, diskFree: 0, memUsed: 0, memTotal: 0 },

  // security
  security: null,
  secScanning: false,

  // diagnostics
  diag: null,
  diagScanning: false,

  // checklist (static definition + local done state)
  checklist: [],
  checkState: {}, // id -> bool

  lastScan: '',
  error: '',

  async refreshQuick() {
    try {
      this.quick = await api.quick()
    } catch (e) {
      /* header gauges are best-effort */
    }
  },

  async runSecurity() {
    this.secScanning = true
    this.error = ''
    try {
      this.security = await api.securityScan()
      this.lastScan = this.security.scanTime
    } catch (e) {
      this.error = e.message
    } finally {
      this.secScanning = false
    }
  },

  async runDiag() {
    this.diagScanning = true
    this.error = ''
    try {
      this.diag = await api.diagScan()
      this.lastScan = this.diag.scanTime
      this.applyChecklistFromScan()
    } catch (e) {
      this.error = e.message
    } finally {
      this.diagScanning = false
    }
  },

  async loadChecklist() {
    if (this.checklist.length) return
    try {
      this.checklist = await api.checklist()
      for (const cat of this.checklist) {
        for (const it of cat.items) {
          if (!(it.id in this.checkState)) this.checkState[it.id] = false
        }
      }
    } catch (e) {
      this.error = e.message
    }
  },

  toggleCheck(id) {
    this.checkState[id] = !this.checkState[id]
  },

  resetChecklist() {
    for (const k of Object.keys(this.checkState)) this.checkState[k] = false
  },

  // After a diagnostics + security scan, auto-mark checklist items.
  applyChecklistFromScan() {
    if (!this.diag) return
    const d = this.diag.data
    const set = (id, ok) => { if (id in this.checkState) this.checkState[id] = ok }
    set('perf-cpu', d.cpu < 80)
    set('perf-mem', d.mem < 80)
    set('perf-disk', d.diskFree > 15)
    set('net-conn', (this.diag.pingTests || []).some(p => p.ok))
    set('net-dns', d.dnsMs >= 0)
    set('stg-smart', d.diskSmart === '正常')

    if (this.security) {
      const byId = {}
      for (const m of this.security.modules) byId[m.id] = m.status === 'clean'
      set('sec-fw', byId['firewall'])
      set('sec-av', byId['defender'])
      set('sec-update', byId['update'])
      set('sec-uac', byId['uac'])
    }
  }
})
