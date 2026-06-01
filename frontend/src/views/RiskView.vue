<script setup>
import { ref, computed } from 'vue'
import { store } from '../store.js'

const diag = computed(() => store.diag)
const risk = computed(() => diag.value ? diag.value.risk : null)

// ESET-style risk slider: 1 = show all, higher = only riskier objects.
const minScore = ref(1)
const kindFilter = ref('all')
const expanded = ref(new Set())

const kinds = [
  { id: 'all', label: '全部' },
  { id: 'process', label: '⚙️ 进程' },
  { id: 'driver', label: '🧩 内核驱动' },
  { id: 'task', label: '🕒 计划任务' }
]

const levelMeta = {
  high: { label: '高风险', color: '#ef4444', cls: 'high' },
  medium: { label: '中风险', color: '#f59e0b', cls: 'medium' },
  low: { label: '低风险', color: '#3b82f6', cls: 'low' },
  safe: { label: '安全', color: '#22c55e', cls: 'ok' }
}

const filtered = computed(() => {
  if (!risk.value) return []
  return risk.value.objects.filter(o =>
    o.score >= minScore.value &&
    (kindFilter.value === 'all' || o.kind === kindFilter.value)
  )
})

function scoreColor(score) {
  if (score >= 7) return '#ef4444'
  if (score >= 5) return '#f59e0b'
  if (score >= 3) return '#3b82f6'
  return '#22c55e'
}

function toggle(i) {
  const s = new Set(expanded.value)
  s.has(i) ? s.delete(i) : s.add(i)
  expanded.value = s
}
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>🎯 风险快照</h2>
        <div class="desc">参考 ESET SysInspector，对进程/驱动/计划任务按数字签名与启发式规则评级 (1-9)</div>
      </div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <template v-else-if="risk">
      <!-- Summary tiles -->
      <div class="grid cols-4" style="margin-bottom:16px">
        <div class="card risk-tile" @click="minScore = 7">
          <div class="rt-num" style="color:#ef4444">{{ risk.high }}</div>
          <div class="rt-lbl">🔴 高风险</div>
        </div>
        <div class="card risk-tile" @click="minScore = 5">
          <div class="rt-num" style="color:#f59e0b">{{ risk.medium }}</div>
          <div class="rt-lbl">🟡 中风险</div>
        </div>
        <div class="card risk-tile" @click="minScore = 3">
          <div class="rt-num" style="color:#3b82f6">{{ risk.low }}</div>
          <div class="rt-lbl">🔵 低风险</div>
        </div>
        <div class="card risk-tile" @click="minScore = 1">
          <div class="rt-num" style="color:#94a3b8">{{ risk.unsigned }}</div>
          <div class="rt-lbl">✍️ 未签名</div>
        </div>
      </div>

      <!-- Risk slider + kind filter -->
      <div class="card" style="margin-bottom:16px">
        <div class="slider-row">
          <span class="slider-lbl">风险过滤 ≥ <b :style="{ color: scoreColor(minScore) }">{{ minScore }}</b></span>
          <input type="range" min="1" max="9" step="1" v-model.number="minScore" class="risk-slider" />
          <span class="slider-hint">向右拖动只显示更可疑的对象</span>
        </div>
        <div class="chips" style="margin-top:14px;margin-bottom:0">
          <div v-for="k in kinds" :key="k.id" class="chip" :class="{ active: kindFilter === k.id }" @click="kindFilter = k.id">
            {{ k.label }}
          </div>
        </div>
      </div>

      <!-- Object table -->
      <div class="card">
        <h3>检测对象 ({{ filtered.length }} / {{ risk.total }})</h3>
        <div class="table-wrap" style="margin-top:12px">
          <table>
            <thead>
              <tr><th style="width:28px"></th><th>风险</th><th>类型</th><th>名称</th><th>签名</th><th>发行商</th><th>路径</th></tr>
            </thead>
            <tbody>
              <template v-for="(o,i) in filtered" :key="i">
                <tr class="row-click" @click="toggle(i)">
                  <td style="text-align:center;color:var(--text-dim)">{{ expanded.has(i) ? '▾' : '▸' }}</td>
                  <td>
                    <span class="risk-badge" :style="{ background: scoreColor(o.score) }">{{ o.score }}</span>
                  </td>
                  <td>{{ o.kindLabel }}</td>
                  <td>{{ o.name }}</td>
                  <td>
                    <span class="sev" :class="o.signed ? 'ok' : (o.signature === '签名无效' ? 'high' : 'medium')">
                      {{ o.signature }}
                    </span>
                  </td>
                  <td>{{ o.publisher || '—' }}</td>
                  <td class="path-cell">{{ o.path || '—' }}</td>
                </tr>
                <tr v-if="expanded.has(i)" class="row-detail">
                  <td></td>
                  <td colspan="6">
                    <div class="sol">
                      <div class="sol-head" :style="{ color: scoreColor(o.score) }">
                        {{ levelMeta[o.level].label }} (评分 {{ o.score }}/9)
                      </div>
                      <div class="sol-reasons">
                        <div class="rsn-lbl">评级依据：</div>
                        <ul>
                          <li v-for="(r,j) in o.reasons" :key="j">{{ r }}</li>
                        </ul>
                      </div>
                      <div v-if="o.pid" class="sol-meta">PID: {{ o.pid }}</div>
                      <div class="sol-fix">💡 建议：{{ o.fix }}</div>
                    </div>
                  </td>
                </tr>
              </template>
              <tr v-if="!filtered.length">
                <td colspan="7" class="empty"><div class="big">✅</div>当前过滤级别下无对象</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.risk-tile { text-align: center; cursor: pointer; transition: border-color .2s; }
.risk-tile:hover { border-color: var(--accent); }
.rt-num { font-size: 34px; font-weight: 800; line-height: 1; }
.rt-lbl { font-size: 13px; color: var(--text-dim); margin-top: 8px; }

.slider-row { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
.slider-lbl { font-size: 14px; min-width: 110px; }
.risk-slider { flex: 1; min-width: 200px; accent-color: var(--accent); cursor: pointer; }
.slider-hint { font-size: 12px; color: var(--text-dim); }

.risk-badge {
  display: inline-block; width: 24px; height: 24px; line-height: 24px;
  text-align: center; border-radius: 6px; color: #fff; font-weight: 700; font-size: 13px;
}
.path-cell { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; color: var(--text-dim); }
.row-click { cursor: pointer; }
.row-detail > td { background: rgba(0,0,0,.18); }
.sol { padding: 8px 4px 12px; }
.sol-head { font-weight: 700; font-size: 14px; margin-bottom: 8px; }
.sol-reasons { font-size: 13px; }
.rsn-lbl { color: var(--text-dim); margin-bottom: 4px; }
.sol-reasons ul { margin: 0; padding-left: 20px; }
.sol-reasons li { line-height: 1.7; }
.sol-meta { font-size: 12px; color: var(--text-dim); margin-top: 8px; font-family: Consolas, monospace; }
.sol-fix { font-size: 13px; color: #93c5fd; margin-top: 8px; }
</style>
