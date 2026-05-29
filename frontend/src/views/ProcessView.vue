<script setup>
import { ref, computed } from 'vue'
import { store } from '../store.js'

const sortKey = ref('cpu')
const diag = computed(() => store.diag)

const procs = computed(() => {
  if (!diag.value) return []
  const list = [...diag.value.processes]
  list.sort((a, b) => b[sortKey.value] - a[sortKey.value])
  return list.slice(0, 100)
})

const sorts = [
  { id: 'cpu', label: 'CPU 排序' },
  { id: 'mem', label: '内存排序' },
  { id: 'total', label: 'I/O 排序' }
]
</script>

<template>
  <div>
    <div class="page-head">
      <div><h2>⚙️ 进程详情</h2></div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <template v-else>
      <div class="chips">
        <div v-for="s in sorts" :key="s.id" class="chip" :class="{ active: sortKey === s.id }" @click="sortKey = s.id">
          {{ s.label }}
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>进程名</th><th>PID</th><th>CPU%</th><th>内存MB</th>
              <th>读MB/s</th><th>写MB/s</th><th>线程</th><th>状态</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in procs" :key="p.pid">
              <td>{{ p.name }}</td><td>{{ p.pid }}</td><td>{{ p.cpu }}%</td>
              <td>{{ p.mem }}</td><td>{{ p.rd }}</td><td>{{ p.wr }}</td><td>{{ p.thr }}</td>
              <td>
                <span class="sev" :class="p.susp ? 'high' : 'ok'">
                  {{ p.susp ? '⚠️ 可疑' : '正常' }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>
