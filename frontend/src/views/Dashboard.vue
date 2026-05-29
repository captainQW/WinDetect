<script setup>
import { computed } from 'vue'
import { store } from '../store.js'
import MetricTile from '../components/MetricTile.vue'
import FindingCard from '../components/FindingCard.vue'

const emit = defineEmits(['open-module', 'navigate'])

const modules = [
  { id: 'firewall', icon: '🧱', name: '防火墙' },
  { id: 'defender', icon: '🛡️', name: 'Defender' },
  { id: 'update', icon: '🔄', name: '系统更新' },
  { id: 'account', icon: '👤', name: '账户安全' },
  { id: 'network', icon: '🌐', name: '网络安全' },
  { id: 'startup', icon: '🚀', name: '启动项' },
  { id: 'uac', icon: '🔐', name: 'UAC' },
  { id: 'shares', icon: '📁', name: '共享与远程' }
]

const sec = computed(() => store.security)
const diag = computed(() => store.diag)
const q = computed(() => store.quick)

const score = computed(() => sec.value ? sec.value.score : 0)
const topFindings = computed(() => sec.value ? sec.value.findings.slice(0, 4) : [])
const topWarnings = computed(() => diag.value ? diag.value.warnings.slice(0, 4) : [])

function modStatus(id) {
  if (!sec.value) return 'pending'
  const m = sec.value.modules.find(m => m.id === id)
  return m ? m.status : 'pending'
}
function modCount(id) {
  if (!sec.value) return 0
  const m = sec.value.modules.find(m => m.id === id)
  return m ? m.findings.length : 0
}
function modText(id) {
  const s = modStatus(id)
  return s === 'clean' ? '正常' : s === 'warn' ? '发现问题' : '待扫描'
}
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>综合仪表盘</h2>
        <div class="desc">安全检测 + 系统诊断全景视图</div>
      </div>
      <div style="display:flex; gap:10px">
        <button class="btn sec" :disabled="store.secScanning" @click="store.runSecurity()">🔒 安全扫描</button>
        <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 系统诊断</button>
      </div>
    </div>

    <!-- Risk banner -->
    <div class="risk-banner">
      <span class="icon">{{ sec ? sec.riskIcon : '🔍' }}</span>
      <div>
        <div style="font-size:18px; font-weight:700">{{ sec ? sec.riskTitle : '尚未执行安全扫描' }}</div>
        <div class="desc">{{ sec ? sec.riskDesc : '点击右上角“安全扫描”开始检测系统安全状况' }}</div>
      </div>
      <div class="score-badge">
        <div class="score-num" :style="{ color: score >= 75 ? 'var(--green)' : score >= 50 ? 'var(--orange)' : 'var(--red)' }">
          {{ score }}
        </div>
        <div class="score-cap">安全分 / 100</div>
      </div>
    </div>

    <div class="grid cols-2">
      <!-- Security card -->
      <div class="card">
        <div class="card-header">
          <h3>🔒 安全状态</h3>
          <button class="btn" :disabled="store.secScanning" @click="store.runSecurity()">扫描</button>
        </div>

        <template v-if="sec">
          <div class="grid cols-4" style="margin-bottom:14px">
            <div v-for="(v,k) in sec.summary" :key="k" class="metric" style="text-align:center">
              <div class="value">{{ v }}</div>
              <div class="sub">{{ k }}</div>
            </div>
          </div>
          <FindingCard v-for="(f,i) in topFindings" :key="i" :finding="f" />
          <div v-if="!topFindings.length" class="empty">
            <div class="big">✅</div>未发现严重问题
          </div>
        </template>
        <div v-else class="empty">
          <div class="big">🔍</div>执行安全扫描
        </div>
      </div>

      <!-- Diagnostics card -->
      <div class="card">
        <div class="card-header">
          <h3>🔬 系统诊断</h3>
          <button class="btn" :disabled="store.diagScanning" @click="store.runDiag()">诊断</button>
        </div>

        <div class="grid cols-2" style="margin-bottom:14px">
          <MetricTile icon="⚡" label="CPU" :value="q.cpu" unit="%" :pct="q.cpu"
            :sub="'用户 ' + Math.round(q.cpu*0.7) + '% / 系统 ' + Math.round(q.cpu*0.3) + '%'" />
          <MetricTile icon="💾" label="内存" :value="q.mem" unit="%" :pct="q.mem"
            :sub="'使用 ' + Math.round(q.memUsed) + 'GB / 总 ' + q.memTotal + 'GB'" />
          <MetricTile icon="💿" label="磁盘 C:" :value="q.disk" unit="%" :pct="q.disk"
            :sub="'剩余 ' + q.diskFree + '%'" />
          <MetricTile icon="🌐" label="网络延迟" :value="diag ? diag.data.netLatency : 0" unit="ms"
            :sub="diag ? ('↑' + diag.data.netUp + ' ↓' + diag.data.netDn + ' KB/s') : '待诊断'" />
        </div>

        <template v-if="diag">
          <div v-for="(w,i) in topWarnings" :key="i" class="finding" :class="w.sev">
            <div class="f-title">{{ w.desc }}</div>
            <div class="f-detail">{{ w.result }}</div>
            <div class="f-fix">💡 {{ w.fix }}</div>
          </div>
          <div v-if="!topWarnings.length" class="empty"><div class="big">✅</div>系统运行正常</div>
        </template>
        <div v-else class="empty"><div class="big">🔬</div>执行系统诊断</div>
      </div>
    </div>

    <!-- Modules -->
    <div class="card" style="margin-top:16px">
      <h3>📦 检测模块状态</h3>
      <div class="desc">点击模块查看详细发现</div>
      <div class="grid cols-4">
        <div v-for="m in modules" :key="m.id" class="card module-card" @click="emit('open-module', m.id)">
          <div class="mod-top">
            <span class="mod-icon">{{ m.icon }}</span>
            <div>
              <div style="font-weight:600">{{ m.name }}</div>
              <div class="sub" :style="{ color: modStatus(m.id)==='warn' ? 'var(--orange)' : modStatus(m.id)==='clean' ? 'var(--green)' : 'var(--text-dim)' }">
                {{ modText(m.id) }}
              </div>
            </div>
            <span v-if="modCount(m.id)" class="badge" style="margin-left:auto; background:var(--red); color:#fff; border-radius:10px; padding:1px 8px; font-size:11px">
              {{ modCount(m.id) }}
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
