<script setup>
import { computed } from 'vue'
import { store } from '../store.js'

const diag = computed(() => store.diag)
const adapters = computed(() => diag.value ? diag.value.adapters : [])
const pings = computed(() => diag.value ? diag.value.pingTests : [])
const conns = computed(() => diag.value ? diag.value.tcpConns : [])
</script>

<template>
  <div>
    <div class="page-head">
      <div><h2>🌐 网络分析</h2></div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <template v-else>
      <div class="grid cols-2" style="margin-bottom:16px">
        <div class="card">
          <h3>网络适配器</h3>
          <div style="margin-top:12px">
            <div v-for="(a,i) in adapters" :key="i" class="metric" style="margin-bottom:10px">
              <div class="label"><span>{{ a.name }}</span><span>{{ a.type }}</span></div>
              <div class="sub">IP: {{ a.ip || '—' }} · MAC: {{ a.mac }} · 速率: {{ a.speed }}</div>
              <div class="sub" style="margin-top:4px">↑{{ a.up_kbps }} KB/s · ↓{{ a.dn_kbps }} KB/s</div>
            </div>
            <div v-if="!adapters.length" class="empty">无活动适配器</div>
          </div>
        </div>
        <div class="card">
          <h3>连通性测试</h3>
          <div style="margin-top:12px">
            <div v-for="(t,i) in pings" :key="i" class="kv-row">
              <span class="k">{{ t.host }}</span>
              <span :style="{ color: t.ok ? 'var(--green)' : 'var(--red)' }">
                {{ t.ok ? t.ms + 'ms' : '超时' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <h3>TCP 连接 (已建立)</h3>
        <div class="table-wrap" style="margin-top:12px">
          <table>
            <thead><tr><th>本地</th><th>远程地址</th><th>端口</th><th>状态</th><th>进程</th></tr></thead>
            <tbody>
              <tr v-for="(c,i) in conns" :key="i">
                <td>{{ c.local }}</td><td>{{ c.remote }}</td><td>{{ c.port }}</td>
                <td><span class="sev ok">{{ c.state }}</span></td><td>{{ c.proc || '—' }}</td>
              </tr>
              <tr v-if="!conns.length"><td colspan="5" class="empty">无已建立连接</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
