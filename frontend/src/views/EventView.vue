<script setup>
import { ref, computed } from 'vue'
import { store } from '../store.js'

const filter = ref('all')
const expanded = ref(new Set())
const copiedIdx = ref(-1)

const diag = computed(() => store.diag)
const events = computed(() => diag.value ? diag.value.data.events : [])

const filtered = computed(() => {
  if (filter.value === 'all') return events.value
  if (filter.value === 'err') return events.value.filter(e => e.lv === 'critical' || e.lv === 'error')
  if (filter.value === 'warn') return events.value.filter(e => e.lv === 'medium')
  return events.value
})

const lvNames = { critical: '严重', error: '错误', medium: '警告', info: '信息' }
const lvClass = { critical: 'critical', error: 'error', medium: 'medium', info: 'info' }

function hasRemedy(e) {
  return (e.steps && e.steps.length) || e.fix || e.cause
}
function toggle(i) {
  const s = new Set(expanded.value)
  s.has(i) ? s.delete(i) : s.add(i)
  expanded.value = s
}
function copyCmd(cmd, i) {
  navigator.clipboard?.writeText(cmd).then(() => {
    copiedIdx.value = i
    setTimeout(() => (copiedIdx.value = -1), 1500)
  })
}

const filters = [
  { id: 'all', label: '全部' },
  { id: 'err', label: '🔴 严重/错误' },
  { id: 'warn', label: '🟡 警告' }
]
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>📋 事件日志</h2>
        <div class="desc">点击行展开可能原因与解决方法</div>
      </div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <template v-else>
      <div class="chips">
        <div v-for="f in filters" :key="f.id" class="chip" :class="{ active: filter === f.id }" @click="filter = f.id">
          {{ f.label }}
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead><tr><th style="width:28px"></th><th>级别</th><th>时间</th><th>来源</th><th>事件ID</th><th>消息</th></tr></thead>
          <tbody>
            <template v-for="(e,i) in filtered" :key="i">
              <tr class="row-click" @click="toggle(i)">
                <td style="text-align:center;color:var(--text-dim)">
                  <span v-if="hasRemedy(e)">{{ expanded.has(i) ? '▾' : '▸' }}</span>
                </td>
                <td><span class="sev" :class="lvClass[e.lv] || 'info'">{{ lvNames[e.lv] || e.lv }}</span></td>
                <td style="white-space:nowrap">{{ e.time }}</td>
                <td>{{ e.src }}</td>
                <td>{{ e.id || '—' }}</td>
                <td>{{ e.msg }}</td>
              </tr>
              <tr v-if="expanded.has(i) && hasRemedy(e)" class="row-detail">
                <td></td>
                <td colspan="5">
                  <div class="sol">
                    <div v-if="e.cause" class="sol-cause">🔍 可能原因：{{ e.cause }}</div>
                    <div class="sol-head">🛠️ 解决方法</div>
                    <ol v-if="e.steps && e.steps.length" class="sol-steps">
                      <li v-for="(s,j) in e.steps" :key="j">{{ s }}</li>
                    </ol>
                    <div v-else class="sol-fix">💡 {{ e.fix }}</div>
                    <div v-if="e.cmd" class="sol-cmd">
                      <code>{{ e.cmd }}</code>
                      <button class="sol-copy" @click.stop="copyCmd(e.cmd, i)">
                        {{ copiedIdx === i ? '已复制' : '复制' }}
                      </button>
                    </div>
                  </div>
                </td>
              </tr>
            </template>
            <tr v-if="!filtered.length"><td colspan="6" class="empty">无匹配事件</td></tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>

<style scoped>
.row-click { cursor: pointer; }
.row-detail > td { background: rgba(0,0,0,.18); }
.sol { padding: 6px 4px 10px; }
.sol-cause { font-size: 13px; color: var(--text-dim); margin-bottom: 8px; }
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
</style>
