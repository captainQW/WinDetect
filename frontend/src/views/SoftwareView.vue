<script setup>
import { computed } from 'vue'
import { store } from '../store.js'

const diag = computed(() => store.diag)
const runtimes = computed(() => diag.value ? diag.value.runtimes : [])
const secUpdates = computed(() => diag.value ? diag.value.secUpdates : [])
const patches = computed(() => diag.value ? diag.value.patches : [])
</script>

<template>
  <div>
    <div class="page-head">
      <div><h2>📦 软件环境</h2></div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <template v-else>
      <div class="grid cols-2" style="margin-bottom:16px">
        <div class="card">
          <h3>运行时 & 框架</h3>
          <div style="margin-top:12px">
            <div v-for="(kv,i) in runtimes" :key="i" class="kv-row">
              <span class="k">{{ kv.k }}</span><span>{{ kv.v }}</span>
            </div>
          </div>
        </div>
        <div class="card">
          <h3>安全 & 更新</h3>
          <div style="margin-top:12px">
            <div v-for="(kv,i) in secUpdates" :key="i" class="kv-row">
              <span class="k">{{ kv.k }}</span><span>{{ kv.v }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <h3>已安装更新 / 补丁</h3>
        <div class="table-wrap" style="margin-top:12px">
          <table>
            <thead><tr><th>KB 编号</th><th>描述</th><th>类型</th><th>发布日期</th><th>严重度</th></tr></thead>
            <tbody>
              <tr v-for="(p,i) in patches" :key="i">
                <td>{{ p.kb }}</td><td>{{ p.desc }}</td><td>{{ p.type }}</td><td>{{ p.date }}</td><td>{{ p.sev }}</td>
              </tr>
              <tr v-if="!patches.length"><td colspan="5" class="empty">无补丁记录</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
