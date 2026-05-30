<script setup>
import { computed } from 'vue'
import { store } from '../store.js'
import MetricTile from '../components/MetricTile.vue'

const diag = computed(() => store.diag)
const d = computed(() => diag.value ? diag.value.data : null)
const hasCounters = computed(() => d.value && d.value.counters)
const problemDevs = computed(() => diag.value ? (diag.value.problemDevs || []) : [])

const cpuCounters = computed(() => {
  if (!d.value) return []
  const rows = [['处理器使用率 (_Total)', d.value.cpu + '%']]
  if (hasCounters.value) {
    rows.push(
      ['用户模式时间', d.value.cpuUser + '%'],
      ['特权模式时间', d.value.cpuKernel + '%'],
      ['中断时间', d.value.cpuInterrupt + '%'],
      ['处理器队列长度', d.value.cpuQueue],
      ['上下文切换/秒', fmtInt(d.value.ctxSwitch)],
      ['系统调用/秒', fmtInt(d.value.sysCalls)],
      ['中断/秒', fmtInt(d.value.interrupts)],
      ['DPC 时间', d.value.dpcLat + '%']
    )
  }
  return rows
})

const memCounters = computed(() => {
  if (!d.value) return []
  const rows = [
    ['物理内存使用', d.value.mem + '%'],
    ['可用物理内存', hasCounters.value
      ? (d.value.memAvailMB / 1024).toFixed(1) + ' GB'
      : (d.value.memTotal - d.value.memUsed).toFixed(1) + ' GB']
  ]
  if (hasCounters.value) {
    rows.push(
      ['已提交内存', d.value.memCommit + ' / ' + d.value.commitLimit + ' GB'],
      ['页面错误/秒', fmtInt(d.value.pageFaults)],
      ['页面文件使用率', d.value.pageFile + '%'],
      ['分页池', d.value.poolPaged + ' MB'],
      ['非分页池', d.value.poolNonPaged + ' MB']
    )
  } else {
    rows.push(['页面文件使用率', d.value.pageFile + '%'])
  }
  return rows
})

const diskCounters = computed(() => {
  if (!d.value) return []
  const rows = [
    ['磁盘读取/秒', d.value.diskRd + ' MB/s'],
    ['磁盘写入/秒', d.value.diskWr + ' MB/s'],
    ['磁盘队列长度', d.value.diskQ],
    ['读取延迟', d.value.diskRdMs + ' ms'],
    ['写入延迟', d.value.diskWrMs + ' ms'],
    ['C: 剩余空间', d.value.diskFree + '%']
  ]
  if (hasCounters.value) {
    rows.push(
      ['磁盘活动时间', d.value.diskBusy + '%'],
      ['磁盘传输/秒 (IOPS)', Math.round(d.value.diskIops)]
    )
  }
  return rows
})

const netCounters = computed(() => {
  if (!d.value) return []
  const rows = [
    ['发送字节/秒', d.value.netUp + ' KB/s'],
    ['接收字节/秒', d.value.netDn + ' KB/s'],
    ['网关 Ping', d.value.gwPing + ' ms'],
    ['TCP 建立连接数', d.value.tcpConn]
  ]
  if (d.value.dnsMs > 0) rows.splice(2, 0, ['DNS 响应延迟', d.value.dnsMs + ' ms'])
  if (hasCounters.value) rows.push(['TCP 重传率', d.value.tcpRetrans + '%'])
  return rows
})

function fmtInt(n) {
  return (n || 0).toLocaleString('en-US')
}
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>🔬 系统诊断总览</h2>
        <div class="desc">参考 perfmon /report 资源与性能摘要</div>
      </div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 重新诊断</button>
    </div>

    <div v-if="!diag" class="empty">
      <div class="big">🔬</div>请先执行系统诊断
      <div style="margin-top:14px">
        <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">▶ 开始</button>
      </div>
    </div>

    <template v-else>
      <!-- Warnings -->
      <div v-if="diag.warnings.length" class="card" style="margin-bottom:16px">
        <h3>⚠️ 诊断警告 ({{ diag.warnings.length }})</h3>
        <div style="margin-top:12px">
          <div v-for="(w,i) in diag.warnings" :key="i" class="finding" :class="w.sev">
            <div class="f-title">{{ w.desc }}</div>
            <div class="f-detail">{{ w.result }} → {{ w.fix }}</div>
          </div>
        </div>
      </div>

      <div v-if="!hasCounters" class="banner-error" style="margin-bottom:16px">
        ⚠️ 未能读取 Windows 性能计数器，部分细分指标已隐藏。请以管理员身份运行后端以获取完整数据。
      </div>

      <!-- Top metrics -->
      <div class="grid cols-4" style="margin-bottom:16px">
        <MetricTile icon="⚡" label="CPU 使用率" :value="d.cpu" unit="%" :pct="d.cpu" />
        <MetricTile icon="💾" label="内存使用" :value="d.mem" unit="%" :pct="d.mem" />
        <MetricTile icon="💿" label="磁盘 C: 剩余" :value="d.diskFree" unit="%" :pct="100 - d.diskFree" />
        <MetricTile icon="🌐" label="网络延迟" :value="d.netLatency" unit="ms"
          :sub="'↑' + d.netUp + ' ↓' + d.netDn + ' KB/s'" />
      </div>

      <!-- Counter summaries -->
      <div class="grid cols-2">
        <div class="card">
          <h3>📊 性能计数器摘要</h3>
          <div style="margin-top:10px">
            <div style="color:var(--text-dim); font-size:12px; margin:8px 0">⚡ 处理器</div>
            <div v-for="(c,i) in cpuCounters" :key="i" class="kv-row">
              <span class="k">{{ c[0] }}</span><span>{{ c[1] }}</span>
            </div>
            <div style="color:var(--text-dim); font-size:12px; margin:12px 0 8px">💾 内存</div>
            <div v-for="(c,i) in memCounters" :key="'m'+i" class="kv-row">
              <span class="k">{{ c[0] }}</span><span>{{ c[1] }}</span>
            </div>
          </div>
        </div>

        <div class="card">
          <h3>📊 I/O 与网络摘要</h3>
          <div style="margin-top:10px">
            <div style="color:var(--text-dim); font-size:12px; margin:8px 0">💿 磁盘 I/O</div>
            <div v-for="(c,i) in diskCounters" :key="'d'+i" class="kv-row">
              <span class="k">{{ c[0] }}</span><span>{{ c[1] }}</span>
            </div>
            <div style="color:var(--text-dim); font-size:12px; margin:12px 0 8px">🌐 网络</div>
            <div v-for="(c,i) in netCounters" :key="'n'+i" class="kv-row">
              <span class="k">{{ c[0] }}</span><span>{{ c[1] }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Problem devices (parity with perfmon /report) -->
      <div v-if="problemDevs.length" class="card" style="margin-top:16px">
        <h3>🚫 问题设备 ({{ problemDevs.length }})</h3>
        <div class="table-wrap" style="margin-top:12px">
          <table>
            <thead><tr><th>设备</th><th>类别</th><th>错误代码</th><th>问题</th></tr></thead>
            <tbody>
              <tr v-for="(dev,i) in problemDevs" :key="i">
                <td>{{ dev.name }}</td>
                <td>{{ dev.class || '—' }}</td>
                <td><span class="sev medium">{{ dev.errorCode }}</span></td>
                <td>{{ dev.problem }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
