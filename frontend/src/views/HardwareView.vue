<script setup>
import { computed } from 'vue'
import { store } from '../store.js'

const diag = computed(() => store.diag)
const sections = computed(() => diag.value ? diag.value.hardware : [])
</script>

<template>
  <div>
    <div class="page-head">
      <div><h2>🖥️ 硬件信息</h2></div>
      <button class="btn diag" :disabled="store.diagScanning" @click="store.runDiag()">🔬 诊断</button>
    </div>

    <div v-if="!diag" class="empty"><div class="big">🔬</div>请先执行系统诊断</div>

    <div v-else class="grid cols-2">
      <div v-for="(sec,i) in sections" :key="i" class="card">
        <h3>{{ sec.icon }} {{ sec.title }}</h3>
        <div style="margin-top:12px">
          <div v-for="(kv,j) in sec.kv" :key="j" class="kv-row">
            <span class="k">{{ kv.k }}</span><span>{{ kv.v }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
