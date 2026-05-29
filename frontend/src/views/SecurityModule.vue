<script setup>
import { computed } from 'vue'
import { store } from '../store.js'
import FindingCard from '../components/FindingCard.vue'

const props = defineProps({ moduleId: String })

const mod = computed(() => {
  if (!store.security) return null
  return store.security.modules.find(m => m.id === props.moduleId) || null
})

const statusText = computed(() => {
  if (!mod.value) return '待扫描'
  return mod.value.status === 'clean' ? '✅ 正常' : mod.value.status === 'warn' ? '⚠️ 异常' : '⏳ 待扫描'
})

// Column headers derived from the first data row.
const columns = computed(() => {
  if (!mod.value || !mod.value.data || !mod.value.data.length) return []
  return Object.keys(mod.value.data[0])
})
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>{{ mod ? mod.icon + ' ' + mod.name : '安全模块' }}</h2>
        <div class="desc">{{ mod ? mod.desc : '' }}</div>
      </div>
      <div style="display:flex; gap:10px; align-items:center">
        <span class="pill" :class="mod && mod.status==='warn' ? 'stop' : 'run'">{{ statusText }}</span>
        <button class="btn sec" :disabled="store.secScanning" @click="store.runSecurity()">▶ 安全扫描</button>
      </div>
    </div>

    <template v-if="mod">
      <div class="card">
        <h3>🚨 发现 ({{ mod.findings.length }})</h3>
        <div style="margin-top:12px">
          <FindingCard v-for="(f,i) in mod.findings" :key="i" :finding="f" />
          <div v-if="!mod.findings.length" class="empty"><div class="big">✅</div>未发现问题</div>
        </div>
      </div>

      <div class="card" style="margin-top:16px">
        <h3>📋 检测数据</h3>
        <div class="table-wrap" style="margin-top:12px">
          <table>
            <thead><tr><th v-for="c in columns" :key="c">{{ c }}</th></tr></thead>
            <tbody>
              <tr v-for="(row,i) in mod.data" :key="i">
                <td v-for="c in columns" :key="c">{{ row[c] || '—' }}</td>
              </tr>
              <tr v-if="!mod.data.length"><td class="empty">无数据</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <div v-else class="empty">
      <div class="big">⏳</div>
      待扫描
      <div style="margin-top:14px">
        <button class="btn sec" :disabled="store.secScanning" @click="store.runSecurity()">▶ 安全扫描</button>
      </div>
    </div>
  </div>
</template>
