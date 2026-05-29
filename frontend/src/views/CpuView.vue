<script setup>
import { computed } from 'vue'
import { store } from '../store.js'
import MetricTile from '../components/MetricTile.vue'

const diag = computed(() => store.diag)
const d = computed(() => diag.value ? diag.value.data : null)
const topCpu = computed(() => diag.value ? diag.value.topCpu : [])
const detail = computed(() => diag.value ? diag.value.cpuDetail : [])
const maxCpu = computed(() => Math.max(1, ...topCpu.value.map(p => p.cpu)))
</script>

<template>
  <div>
    <div class="page-head">
      <div><h2>⚡ CPU 分析</h2></div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <template v-else>
      <div class="grid cols-2" style="margin-bottom:16px">
        <div class="card">
          <h3>利用率</h3>
          <div style="margin-top:12px">
            <MetricTile label="总使用率" :value="d.cpu" unit="%" :pct="d.cpu" />
            <div style="height:10px"></div>
            <MetricTile label="用户模式" :value="Math.round(d.cpu*0.72)" unit="%" :pct="d.cpu*0.72" />
            <div style="height:10px"></div>
            <MetricTile label="内核模式" :value="Math.round(d.cpu*0.28)" unit="%" :pct="d.cpu*0.28" />
            <div style="height:10px"></div>
            <MetricTile label="DPC 延迟" :value="d.dpcLat" unit=" μs" />
          </div>
        </div>
        <div class="card">
          <h3>处理器详情</h3>
          <div style="margin-top:12px">
            <div v-for="(kv,i) in detail" :key="i" class="kv-row">
              <span class="k">{{ kv.k }}</span><span>{{ kv.v }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <h3>⚡ CPU 高占用进程</h3>
        <div class="table-wrap" style="margin-top:12px">
          <table>
            <thead><tr><th>进程名</th><th>PID</th><th>CPU%</th><th>占比</th><th>描述</th></tr></thead>
            <tbody>
              <tr v-for="p in topCpu" :key="p.pid">
                <td>{{ p.name }}</td><td>{{ p.pid }}</td><td>{{ p.cpu }}%</td>
                <td style="width:160px">
                  <div class="bar"><span :style="{ width: (p.cpu/maxCpu*100)+'%' }"></span></div>
                </td>
                <td>{{ p.desc }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
