<script setup>
import { computed } from 'vue'
import { store } from '../store.js'

const diag = computed(() => store.diag)
const disks = computed(() => diag.value ? diag.value.disks : [])
const diskIO = computed(() => diag.value ? diag.value.diskIo : [])
const topIO = computed(() => diag.value ? diag.value.topIo : [])
const smart = computed(() => diag.value ? diag.value.data.diskSmart : '')
</script>

<template>
  <div>
    <div class="page-head">
      <div><h2>💿 磁盘分析</h2></div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <template v-else>
      <div class="grid cols-2" style="margin-bottom:16px">
        <div class="card">
          <h3>磁盘使用</h3>
          <div style="margin-top:12px">
            <div v-for="(d,i) in disks" :key="i" class="metric" style="margin-bottom:10px">
              <div class="label">
                <span>{{ d.ltr }} ({{ d.fs }})</span><span>{{ d.usePct }}%</span>
              </div>
              <div class="bar"><span :style="{ width: d.usePct + '%', background: d.usePct > 85 ? 'var(--red)' : 'var(--accent)' }"></span></div>
              <div class="sub">已用 {{ d.used }}GB · 剩余 {{ d.free }}GB · 总计 {{ d.total }}GB · {{ d.type }}</div>
            </div>
          </div>
        </div>
        <div class="card">
          <h3>I/O 性能</h3>
          <div style="margin-top:12px">
            <div v-for="(kv,i) in diskIO" :key="i" class="kv-row">
              <span class="k">{{ kv.k }}</span><span>{{ kv.v }}</span>
            </div>
            <div class="kv-row">
              <span class="k">S.M.A.R.T. 状态</span>
              <span :style="{ color: smart === '正常' ? 'var(--green)' : 'var(--orange)' }">✅ {{ smart }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <h3>💿 磁盘高 I/O 进程</h3>
        <div class="table-wrap" style="margin-top:12px">
          <table>
            <thead><tr><th>进程名</th><th>PID</th><th>读取 MB/s</th><th>写入 MB/s</th><th>总 I/O</th></tr></thead>
            <tbody>
              <tr v-for="p in topIO" :key="p.pid">
                <td>{{ p.name }}</td><td>{{ p.pid }}</td><td>{{ p.rd }}</td><td>{{ p.wr }}</td><td>{{ p.total }} MB/s</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
