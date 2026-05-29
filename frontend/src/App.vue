<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { store } from './store.js'

import Dashboard from './views/Dashboard.vue'
import SecurityFindings from './views/SecurityFindings.vue'
import SecurityModule from './views/SecurityModule.vue'
import DiagOverview from './views/DiagOverview.vue'
import CpuView from './views/CpuView.vue'
import MemoryView from './views/MemoryView.vue'
import DiskView from './views/DiskView.vue'
import NetworkView from './views/NetworkView.vue'
import ProcessView from './views/ProcessView.vue'
import ServiceView from './views/ServiceView.vue'
import EventView from './views/EventView.vue'
import HardwareView from './views/HardwareView.vue'
import SoftwareView from './views/SoftwareView.vue'
import ChecklistView from './views/ChecklistView.vue'
import ReportView from './views/ReportView.vue'

const current = ref('dashboard')
const currentModule = ref('')
const collapsed = ref(false)

const securityNav = [
  { id: 'firewall', icon: '🧱', name: '防火墙' },
  { id: 'defender', icon: '🛡️', name: 'Defender 防病毒' },
  { id: 'update', icon: '🔄', name: '系统更新' },
  { id: 'account', icon: '👤', name: '账户安全' },
  { id: 'network', icon: '🌐', name: '网络安全' },
  { id: 'startup', icon: '🚀', name: '启动项' },
  { id: 'uac', icon: '🔐', name: '用户账户控制' },
  { id: 'shares', icon: '📁', name: '共享与远程' }
]

const diagNav = [
  { id: 'diag', icon: '📈', name: '诊断总览' },
  { id: 'cpu', icon: '⚡', name: 'CPU' },
  { id: 'memory', icon: '💾', name: '内存' },
  { id: 'disk', icon: '💿', name: '磁盘' },
  { id: 'network-diag', icon: '🌐', name: '网络' },
  { id: 'process', icon: '⚙️', name: '进程' },
  { id: 'service', icon: '🔧', name: '服务' },
  { id: 'event', icon: '📋', name: '事件日志' },
  { id: 'hardware', icon: '🖥️', name: '硬件信息' },
  { id: 'software', icon: '📦', name: '软件环境' }
]

const critCount = computed(() => {
  if (!store.security) return 0
  return store.security.findings.filter(f => f.sev === 'critical').length
})

function moduleFindingCount(id) {
  if (!store.security) return 0
  const m = store.security.modules.find(m => m.id === id)
  return m ? m.findings.length : 0
}

const diagDone = computed(() => {
  let done = 0, total = 0
  for (const cat of store.checklist) {
    for (const it of cat.items) {
      total++
      if (store.checkState[it.id]) done++
    }
  }
  return { done, total }
})

const pageTitles = {
  dashboard: '综合仪表盘',
  'sec-findings': '安全发现',
  diag: '系统诊断总览',
  cpu: 'CPU 分析', memory: '内存分析', disk: '磁盘分析',
  'network-diag': '网络分析', process: '进程详情', service: '服务状态',
  event: '事件日志', hardware: '硬件信息', software: '软件环境',
  checklist: '系统检查清单', report: '导出报告'
}

const pageTitle = computed(() => {
  if (current.value === 'sec-module') {
    const m = securityNav.find(m => m.id === currentModule.value)
    return m ? m.name : '安全模块'
  }
  return pageTitles[current.value] || 'WinDiag Pro'
})

function go(view, mod) {
  current.value = view
  if (mod) currentModule.value = mod
}

function openModule(id) {
  currentModule.value = id
  current.value = 'sec-module'
}

let timer = null
onMounted(async () => {
  await store.refreshQuick()
  await store.loadChecklist()
  timer = setInterval(() => store.refreshQuick(), 5000)
})
onUnmounted(() => clearInterval(timer))

const viewComp = computed(() => {
  switch (current.value) {
    case 'dashboard': return Dashboard
    case 'sec-findings': return SecurityFindings
    case 'sec-module': return SecurityModule
    case 'diag': return DiagOverview
    case 'cpu': return CpuView
    case 'memory': return MemoryView
    case 'disk': return DiskView
    case 'network-diag': return NetworkView
    case 'process': return ProcessView
    case 'service': return ServiceView
    case 'event': return EventView
    case 'hardware': return HardwareView
    case 'software': return SoftwareView
    case 'checklist': return ChecklistView
    case 'report': return ReportView
    default: return Dashboard
  }
})
</script>

<template>
  <div class="layout">
    <!-- Scan overlay -->
    <div v-if="store.secScanning || store.diagScanning" class="scan-overlay">
      <div style="font-size:42px">{{ store.secScanning ? '🛡️' : '🔬' }}</div>
      <div class="spinner"></div>
      <div>{{ store.secScanning ? '安全扫描' : '系统诊断' }}进行中...</div>
      <div class="score-cap">正在采集系统数据，请稍候</div>
    </div>

    <!-- Sidebar -->
    <aside class="sidebar" :class="{ collapsed }">
      <div class="brand">
        <span class="logo">🛡️</span>
        <div>
          <div class="title">WinDiag Pro</div>
          <div class="sub">v5.0 诊断 & 安全</div>
        </div>
      </div>

      <div class="nav-section">总览</div>
      <div class="nav-item" :class="{ active: current === 'dashboard' }" @click="go('dashboard')">
        📊 综合仪表盘
      </div>

      <div class="nav-section">🔒 安全检测</div>
      <div class="nav-item" :class="{ active: current === 'sec-findings' }" @click="go('sec-findings')">
        🚨 安全发现
        <span v-if="critCount" class="badge">{{ critCount }}</span>
      </div>
      <div v-for="m in securityNav" :key="m.id" class="nav-item"
           :class="{ active: current === 'sec-module' && currentModule === m.id }"
           @click="openModule(m.id)">
        {{ m.icon }} {{ m.name }}
        <span v-if="moduleFindingCount(m.id)" class="badge">{{ moduleFindingCount(m.id) }}</span>
      </div>

      <div class="nav-section">🔬 系统诊断</div>
      <div v-for="d in diagNav" :key="d.id" class="nav-item"
           :class="{ active: current === d.id }" @click="go(d.id)">
        {{ d.icon }} {{ d.name }}
      </div>
      <div class="nav-item" :class="{ active: current === 'checklist' }" @click="go('checklist')">
        ✅ 检查清单
        <span class="badge muted">{{ diagDone.done }}/{{ diagDone.total }}</span>
      </div>

      <div class="nav-section">工具</div>
      <div class="nav-item" :class="{ active: current === 'report' }" @click="go('report')">
        📄 导出报告
      </div>

      <div class="sidebar-footer">WinDiag Pro v5.0 — 仅供参考</div>
    </aside>

    <!-- Main -->
    <div class="main">
      <header class="topbar">
        <span class="hamburger" @click="collapsed = !collapsed">☰</span>
        <span class="page-title">{{ pageTitle }}</span>
        <div class="spacer"></div>
        <span class="status">
          {{ (store.secScanning || store.diagScanning) ? '扫描中' : (store.lastScan ? '上次: ' + store.lastScan : '待扫描') }}
        </span>
        <button class="btn sec" :disabled="store.secScanning" @click="store.runSecurity()">🔒 安全扫描</button>
        <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 系统诊断</button>
      </header>

      <main class="content">
        <div v-if="store.error" class="banner-error">⚠️ {{ store.error }}</div>
        <component :is="viewComp" :module-id="currentModule" @open-module="openModule" @navigate="go" />
      </main>
    </div>
  </div>
</template>
