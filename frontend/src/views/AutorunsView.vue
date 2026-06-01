<script setup>
import { ref, computed } from 'vue'
import { store } from '../store.js'

const diag = computed(() => store.diag)
const autoruns = computed(() => diag.value ? (diag.value.autoruns || []) : [])

const riskFilter = ref('all')
const hideTrusted = ref(false)

const riskMeta = {
  high: { label: '🔴 高风险', cls: 'high' },
  medium: { label: '🟡 中风险', cls: 'medium' },
  low: { label: '🔵 低风险', cls: 'low' },
  safe: { label: '🟢 安全', cls: 'ok' }
}

const counts = computed(() => {
  const c = { all: autoruns.value.length, high: 0, medium: 0, low: 0, safe: 0 }
  for (const a of autoruns.value) if (c[a.risk] !== undefined) c[a.risk]++
  return c
})

const filters = [
  { id: 'all', label: '全部' },
  { id: 'high', label: '🔴 高风险' },
  { id: 'medium', label: '🟡 中风险' },
  { id: 'low', label: '🔵 低风险' }
]

const filtered = computed(() => {
  let list = autoruns.value
  if (riskFilter.value !== 'all') list = list.filter(a => a.risk === riskFilter.value)
  if (hideTrusted.value) list = list.filter(a => a.risk !== 'safe')
  return list
})
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>🚀 自启动项</h2>
        <div class="desc">参考 Sysinternals Autoruns，扫描注册表/Winlogon/服务/启动文件夹/映像劫持等持久化位置并验证签名</div>
      </div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <template v-else>
      <div class="grid cols-4" style="margin-bottom:16px">
        <div class="card risk-tile"><div class="rt-num" style="color:#ef4444">{{ counts.high }}</div><div class="rt-lbl">🔴 高风险</div></div>
        <div class="card risk-tile"><div class="rt-num" style="color:#f59e0b">{{ counts.medium }}</div><div class="rt-lbl">🟡 中风险</div></div>
        <div class="card risk-tile"><div class="rt-num" style="color:#3b82f6">{{ counts.low }}</div><div class="rt-lbl">🔵 低风险</div></div>
        <div class="card risk-tile"><div class="rt-num" style="color:#22c55e">{{ counts.safe }}</div><div class="rt-lbl">🟢 安全</div></div>
      </div>

      <div class="chips">
        <div v-for="f in filters" :key="f.id" class="chip" :class="{ active: riskFilter === f.id }" @click="riskFilter = f.id">
          {{ f.label }} ({{ counts[f.id] }})
        </div>
        <label class="chip toggle" :class="{ active: hideTrusted }" @click="hideTrusted = !hideTrusted">
          {{ hideTrusted ? '☑' : '☐' }} 隐藏可信项
        </label>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>风险</th><th>类别</th><th>名称</th><th>签名</th><th>发行商</th><th>命令/路径</th></tr>
          </thead>
          <tbody>
            <tr v-for="(a,i) in filtered" :key="i">
              <td><span class="sev" :class="riskMeta[a.risk].cls">{{ riskMeta[a.risk].label }}</span></td>
              <td style="white-space:nowrap">{{ a.category }}</td>
              <td>{{ a.name }}</td>
              <td>
                <span class="sev" :class="a.signed ? 'ok' : (a.signature === '签名无效' ? 'high' : 'medium')">
                  {{ a.signature }}
                </span>
              </td>
              <td>{{ a.publisher || '—' }}</td>
              <td class="cmd-cell" :title="a.command">{{ a.command }}</td>
            </tr>
            <tr v-if="!filtered.length"><td colspan="6" class="empty"><div class="big">✅</div>无匹配的自启动项</td></tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>

<style scoped>
.risk-tile { text-align: center; }
.rt-num { font-size: 30px; font-weight: 800; line-height: 1; }
.rt-lbl { font-size: 12px; color: var(--text-dim); margin-top: 6px; }
.cmd-cell { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; color: var(--text-dim); font-family: Consolas, monospace; }
.chip.toggle { user-select: none; }
</style>
