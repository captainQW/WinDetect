<script setup>
import { ref, computed } from 'vue'
import { store } from '../store.js'

const filter = ref('all')

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
        <div class="desc">共 {{ findings.length }} 项发现</div>
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
            <th>时间</th><th>级别</th><th>模块</th><th>描述</th><th>详情</th><th>修复建议</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(f,i) in filtered" :key="i">
            <td style="white-space:nowrap">{{ f.time }}</td>
            <td><span class="sev" :class="f.sev">{{ sevNames[f.sev] || f.sev }}</span></td>
            <td>{{ f.cat }}</td>
            <td>{{ f.desc }}</td>
            <td>{{ f.detail || '—' }}</td>
            <td>{{ f.fix }}</td>
          </tr>
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
