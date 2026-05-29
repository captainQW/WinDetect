<script setup>
import { ref, computed } from 'vue'
import { store } from '../store.js'

const filter = ref('all')
const diag = computed(() => store.diag)

const services = computed(() => {
  if (!diag.value) return []
  const list = diag.value.services
  if (filter.value === 'running') return list.filter(s => s.state === 'Running')
  if (filter.value === 'stopped') return list.filter(s => s.state !== 'Running')
  return list
})

const filters = [
  { id: 'all', label: '全部' },
  { id: 'running', label: '运行中' },
  { id: 'stopped', label: '已停止' }
]
</script>

<template>
  <div>
    <div class="page-head">
      <div><h2>🔧 服务状态</h2></div>
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
          <thead><tr><th>服务名</th><th>显示名</th><th>状态</th><th>启动</th><th>账户</th></tr></thead>
          <tbody>
            <tr v-for="(s,i) in services" :key="i">
              <td>{{ s.name }}</td><td>{{ s.disp }}</td>
              <td><span class="sev" :class="s.state === 'Running' ? 'ok' : 'info'">{{ s.state === 'Running' ? '运行中' : '已停止' }}</span></td>
              <td>{{ s.start }}</td><td>{{ s.acct }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>
