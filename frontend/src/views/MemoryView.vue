<script setup>
import { computed } from 'vue'
import { store } from '../store.js'

const diag = computed(() => store.diag)
const detail = computed(() => diag.value ? diag.value.memDetail : [])
const compose = computed(() => diag.value ? diag.value.memCompose : [])
const topMem = computed(() => diag.value ? diag.value.topMem : [])
const maxMem = computed(() => Math.max(1, ...topMem.value.map(p => p.mem)))
</script>

<template>
  <div>
    <div class="page-head">
      <div><h2>💾 内存分析</h2></div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <template v-else>
      <div class="grid cols-2" style="margin-bottom:16px">
        <div class="card">
          <h3>内存使用</h3>
          <div style="margin-top:12px">
            <div v-for="(kv,i) in detail" :key="i" class="kv-row">
              <span class="k">{{ kv.k }}</span><span>{{ kv.v }}</span>
            </div>
          </div>
        </div>
        <div class="card">
          <h3>内存构成</h3>
          <div style="margin-top:12px">
            <div v-for="(kv,i) in compose" :key="i" class="kv-row">
              <span class="k">{{ kv.k }}</span><span>{{ kv.v }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <h3>💾 内存高占用进程</h3>
        <div class="table-wrap" style="margin-top:12px">
          <table>
            <thead><tr><th>进程名</th><th>PID</th><th>工作集</th><th>占比</th><th>私有</th></tr></thead>
            <tbody>
              <tr v-for="p in topMem" :key="p.pid">
                <td>{{ p.name }}</td><td>{{ p.pid }}</td><td>{{ p.mem }} MB</td>
                <td style="width:160px">
                  <div class="bar"><span :style="{ width: (p.mem/maxMem*100)+'%' }"></span></div>
                </td>
                <td>{{ p.priv }} MB</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
