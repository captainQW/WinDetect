<script setup>
import { computed } from 'vue'
import { store } from '../store.js'

const diag = computed(() => store.diag)
const rel = computed(() => diag.value ? diag.value.reliability : null)

const typeIcons = {
  '应用崩溃': '💥', '应用无响应': '🥶', '系统崩溃 (蓝屏)': '🟦',
  '异常关机': '⚡', '服务意外终止': '🔧', '其他': '•'
}

const indexColor = computed(() => {
  if (!rel.value) return 'var(--text-dim)'
  if (rel.value.index >= 7) return 'var(--green)'
  if (rel.value.index >= 4) return 'var(--orange)'
  return 'var(--red)'
})

const summary = computed(() => {
  if (!rel.value) return []
  return [
    ['应用崩溃', rel.value.appCrashes, '💥'],
    ['应用无响应', rel.value.appHangs, '🥶'],
    ['系统蓝屏', rel.value.bsods, '🟦'],
    ['服务故障', rel.value.svcFailures, '🔧'],
    ['异常关机', rel.value.ungracefulShutdowns, '⚡']
  ]
})
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>📉 可靠性检查</h2>
        <div class="desc">参考 Windows 可靠性监视器 (perfmon /rel)，统计近 {{ rel ? rel.windowDays : 14 }} 天系统稳定性</div>
      </div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <template v-else-if="rel">
      <div class="grid cols-2" style="margin-bottom:16px">
        <div class="card" style="display:flex;align-items:center;gap:24px">
          <div style="text-align:center">
            <div style="font-size:54px;font-weight:800;line-height:1" :style="{color:indexColor}">
              {{ rel.index.toFixed(1) }}
            </div>
            <div class="score-cap">稳定性指数 / 10</div>
          </div>
          <div>
            <div style="font-size:18px;font-weight:700" :style="{color:indexColor}">
              {{ rel.level === '稳定' ? '🟢 ' : rel.level === '一般' ? '🟠 ' : '🔴 ' }}{{ rel.level }}
            </div>
            <div class="desc" style="margin-top:6px">
              近 {{ rel.windowDays }} 天共记录 {{ rel.events.length }} 起稳定性事件。
              指数越接近 10 表示系统越稳定。
            </div>
          </div>
        </div>
        <div class="card">
          <h3>事件统计</h3>
          <div style="margin-top:12px">
            <div v-for="(s,i) in summary" :key="i" class="kv-row">
              <span class="k">{{ s[2] }} {{ s[0] }}</span>
              <span :style="{ color: s[1] > 0 ? 'var(--orange)' : 'var(--green)', fontWeight: 600 }">{{ s[1] }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <h3>🕒 稳定性事件时间线</h3>
        <div class="table-wrap" style="margin-top:12px">
          <table>
            <thead><tr><th>时间</th><th>类型</th><th>来源</th><th>详情</th><th>解决方法</th></tr></thead>
            <tbody>
              <tr v-for="(e,i) in rel.events" :key="i">
                <td style="white-space:nowrap">{{ e.time }}</td>
                <td><span class="sev" :class="e.sev">{{ typeIcons[e.type] || '•' }} {{ e.type }}</span></td>
                <td>{{ e.source }}</td>
                <td>{{ e.detail }}</td>
                <td style="color:#93c5fd">💡 {{ e.fix }}</td>
              </tr>
              <tr v-if="!rel.events.length">
                <td colspan="5" class="empty"><div class="big">✅</div>近 {{ rel.windowDays }} 天未发现稳定性问题</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
