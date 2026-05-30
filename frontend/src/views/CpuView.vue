<script setup>
import { computed } from 'vue'
import { store } from '../store.js'
import MetricTile from '../components/MetricTile.vue'

const diag = computed(() => store.diag)
const d = computed(() => diag.value ? diag.value.data : null)
const topCpu = computed(() => diag.value ? diag.value.topCpu : [])
const detail = computed(() => diag.value ? diag.value.cpuDetail : [])
const maxCpu = computed(() => Math.max(1, ...topCpu.value.map(p => p.cpu)))
const hasCounters = computed(() => d.value && d.value.counters)
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
            <template v-if="hasCounters">
              <div style="height:10px"></div>
              <MetricTile label="用户模式" :value="d.cpuUser" unit="%" :pct="d.cpuUser" />
              <div style="height:10px"></div>
              <MetricTile label="内核模式" :value="d.cpuKernel" unit="%" :pct="d.cpuKernel" />
              <div style="height:10px"></div>
              <MetricTile label="中断时间" :value="d.cpuInterrupt" unit="%" :pct="d.cpuInterrupt" />
              <div style="height:10px"></div>
              <MetricTile label="处理器队列长度" :value="d.cpuQueue" unit="" />
              <div style="height:10px"></div>
              <MetricTile label="DPC 时间" :value="d.dpcLat" unit="%" :pct="d.dpcLat" />
            </template>
          </div>
        </div>
        <div class="card">
          <h3>处理器详情</h3>
          <div style="margin-top:12px">
            <div v-for="(kv,i) in detail" :key="i" class="kv-row">
              <span class="k">{{ kv.k }}</span><span>{{ kv.v }}</span>
            </div>
            <template v-if="hasCounters">
              <div class="kv-row"><span class="k">上下文切换/秒</span><span>{{ (d.ctxSwitch||0).toLocaleString('en-US') }}</span></div>
              <div class="kv-row"><span class="k">系统调用/秒</span><span>{{ (d.sysCalls||0).toLocaleString('en-US') }}</span></div>
              <div class="kv-row"><span class="k">中断/秒</span><span>{{ (d.interrupts||0).toLocaleString('en-US') }}</span></div>
            </template>
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
