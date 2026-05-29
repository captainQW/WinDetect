<script setup>
import { ref, computed } from 'vue'
import { store } from '../store.js'

const filter = ref('all')
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

const filters = [
  { id: 'all', label: '全部' },
  { id: 'err', label: '🔴 严重/错误' },
  { id: 'warn', label: '🟡 警告' }
]
</script>

<template>
  <div>
    <div class="page-head">
      <div><h2>📋 事件日志</h2></div>
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
          <thead><tr><th>级别</th><th>时间</th><th>来源</th><th>消息</th></tr></thead>
          <tbody>
            <tr v-for="(e,i) in filtered" :key="i">
              <td><span class="sev" :class="lvClass[e.lv] || 'info'">{{ lvNames[e.lv] || e.lv }}</span></td>
              <td style="white-space:nowrap">{{ e.time }}</td>
              <td>{{ e.src }}</td>
              <td>{{ e.msg }}</td>
            </tr>
            <tr v-if="!filtered.length"><td colspan="4" class="empty">无匹配事件</td></tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>
