<script setup>
import { reactive, computed } from 'vue'
import { store } from '../store.js'
import { api } from '../api.js'

const meta = reactive({
  computer: '',
  os: '',
  auditor: '',
  date: new Date().toISOString().slice(0, 10),
  summary: ''
})

const busy = reactive({ html: false, json: false, csv: false })

const hasData = computed(() => store.security || store.diag)

async function exp(kind) {
  busy[kind] = true
  try {
    if (kind === 'html') await api.exportHTML(meta)
    else if (kind === 'json') await api.exportJSON(meta)
    else await api.exportCSV(meta)
  } catch (e) {
    store.error = e.message
  } finally {
    busy[kind] = false
  }
}
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>📄 导出报告</h2>
        <div class="desc">生成安全检测与系统诊断的综合报告</div>
      </div>
    </div>

    <div v-if="!hasData" class="banner-error">
      ⚠️ 尚无扫描数据，请先执行“安全扫描”或“系统诊断”，报告将包含已完成的扫描结果。
    </div>

    <div class="card" style="max-width:680px">
      <div class="grid cols-2">
        <div class="field">
          <label>计算机名</label>
          <input class="input" v-model="meta.computer" placeholder="例如 DESKTOP-XXXX" />
        </div>
        <div class="field">
          <label>操作系统</label>
          <input class="input" v-model="meta.os" placeholder="例如 Windows 11 Pro" />
        </div>
        <div class="field">
          <label>检测人</label>
          <input class="input" v-model="meta.auditor" placeholder="姓名" />
        </div>
        <div class="field">
          <label>日期</label>
          <input class="input" type="date" v-model="meta.date" />
        </div>
      </div>
      <div class="field">
        <label>摘要</label>
        <textarea class="input" v-model="meta.summary" placeholder="本次检测的总体说明（可选）"></textarea>
      </div>

      <div style="display:flex; gap:10px; margin-top:8px">
        <button class="btn primary" :disabled="busy.html" @click="exp('html')">🌐 HTML 报告</button>
        <button class="btn" :disabled="busy.json" @click="exp('json')">💾 JSON</button>
        <button class="btn" :disabled="busy.csv" @click="exp('csv')">📋 CSV</button>
      </div>
    </div>

    <div class="card" style="max-width:680px; margin-top:16px">
      <h3>当前可用数据</h3>
      <div style="margin-top:10px">
        <div class="kv-row">
          <span class="k">安全扫描</span>
          <span>{{ store.security ? '✅ ' + store.security.scanTime + ' (得分 ' + store.security.score + ')' : '未执行' }}</span>
        </div>
        <div class="kv-row">
          <span class="k">系统诊断</span>
          <span>{{ store.diag ? '✅ ' + store.diag.scanTime : '未执行' }}</span>
        </div>
      </div>
    </div>
  </div>
</template>
