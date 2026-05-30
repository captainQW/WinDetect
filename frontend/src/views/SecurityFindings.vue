<script setup>
import { ref, computed } from 'vue'
import { store } from '../store.js'

const filter = ref('all')
const expanded = ref(new Set())

const sevNames = { critical: '严重', high: '高危', medium: '中危', low: '低危' }

const findings = computed(() => store.security ? store.security.findings : [])

const counts = computed(() => {
  const c = { all: findings.value.length, critical: 0, high: 0, medium: 0, low: 0 }
  for (const f of findings.value) if (c[f.sev] !== undefined) c[f.sev]++
  return c
})

const filtered = computed(() => {
  if (filter.value === 'all') return findings.value
  return findings.value.filter(f => f.sev === filter.value)
})

function toggle(i) {
  const s = new Set(expanded.value)
  s.has(i) ? s.delete(i) : s.add(i)
  expanded.value = s
}

function hasSolution(f) {
  return (f.steps && f.steps.length) || f.cmd
}

const copiedIdx = ref(-1)
function copyCmd(cmd, i) {
  navigator.clipboard?.writeText(cmd).then(() => {
    copiedIdx.value = i
    setTimeout(() => (copiedIdx.value = -1), 1500)
  })
}

const chips = [
  { id: 'all', label: '全部' },
  { id: 'critical', label: '🔴 严重' },
  { id: 'high', label: '🟠 高危' },
  { id: 'medium', label: '🟡 中危' },
  { id: 'low', label: '🔵 低危' }
]
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>🚨 安全发现</h2>
        <div class="desc">共 {{ findings.length }} 项发现 · 点击行展开详细解决方法</div>
      </div>
      <button class="btn sec" :disabled="store.secScanning" @click="store.runSecurity()">🔒 重新扫描</button>
    </div>

    <div class="chips">
      <div v-for="c in chips" :key="c.id" class="chip" :class="{ active: filter === c.id }" @click="filter = c.id">
        {{ c.label }} ({{ counts[c.id] }})
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th style="width:28px"></th>
            <th>时间</th><th>级别</th><th>模块</th><th>描述</th><th>详情</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="(f,i) in filtered" :key="i">
            <tr class="row-click" @click="toggle(i)">
              <td style="text-align:center;color:var(--text-dim)">
                <span v-if="hasSolution(f)">{{ expanded.has(i) ? '▾' : '▸' }}</span>
              </td>
              <td style="white-space:nowrap">{{ f.time }}</td>
              <td><span class="sev" :class="f.sev">{{ sevNames[f.sev] || f.sev }}</span></td>
              <td>{{ f.cat }}</td>
              <td>{{ f.desc }}</td>
              <td>{{ f.detail || '—' }}</td>
            </tr>
            <tr v-if="expanded.has(i)" class="row-detail">
              <td></td>
              <td colspan="5">
                <div class="sol">
                  <div class="sol-head">🛠️ 解决方法</div>
                  <ol v-if="f.steps && f.steps.length" class="sol-steps">
                    <li v-for="(s,j) in f.steps" :key="j">{{ s }}</li>
                  </ol>
                  <div v-else class="sol-fix">💡 {{ f.fix }}</div>
                  <div v-if="f.cmd" class="sol-cmd">
                    <code>{{ f.cmd }}</code>
                    <button class="sol-copy" @click.stop="copyCmd(f.cmd, i)">
                      {{ copiedIdx === i ? '已复制' : '复制' }}
                    </button>
                  </div>
                  <div v-if="f.ref" class="sol-ref">ℹ️ {{ f.ref }}</div>
                </div>
              </td>
            </tr>
          </template>
          <tr v-if="!filtered.length">
            <td colspan="6" class="empty">
              {{ store.security ? '暂无匹配项' : '请先执行安全扫描' }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.row-click { cursor: pointer; }
.row-detail > td { background: rgba(0,0,0,.18); }
.sol { padding: 6px 4px 10px; }
.sol-head { font-weight: 600; font-size: 13px; margin-bottom: 6px; }
.sol-steps { margin: 0; padding-left: 20px; }
.sol-steps li { font-size: 13px; line-height: 1.8; color: var(--text-dim); }
.sol-fix { font-size: 13px; color: #93c5fd; }
.sol-cmd {
  display: flex; align-items: center; gap: 8px; margin-top: 10px; padding: 8px 10px;
  background: rgba(0,0,0,.3); border: 1px solid var(--border); border-radius: 6px;
  font-family: Consolas, monospace;
}
.sol-cmd code { flex: 1; font-size: 12.5px; color: #7dd3fc; white-space: pre-wrap; word-break: break-all; }
.sol-copy {
  flex-shrink: 0; cursor: pointer; font-size: 12px; padding: 3px 10px; border-radius: 4px;
  border: 1px solid var(--border); background: var(--panel-2); color: var(--text);
}
.sol-copy:hover { background: var(--accent); color: #fff; }
.sol-ref { margin-top: 8px; font-size: 12px; color: var(--text-dim); }
</style>
