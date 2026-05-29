<script setup>
import { ref, computed } from 'vue'
import { store } from '../store.js'

const expanded = ref({})

const total = computed(() => {
  let done = 0, all = 0
  for (const cat of store.checklist) {
    for (const it of cat.items) { all++; if (store.checkState[it.id]) done++ }
  }
  return { done, all, pct: all ? Math.round(done / all * 100) : 0 }
})

function catDone(cat) {
  return cat.items.filter(it => store.checkState[it.id]).length
}

function toggleCat(id) {
  expanded.value[id] = !expanded.value[id]
}

async function autoScan() {
  await store.runDiag()
  if (!store.security) await store.runSecurity()
  else store.applyChecklistFromScan()
}

function copyCmd(cmd) {
  navigator.clipboard?.writeText(cmd)
}
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h2>✅ 系统检查清单</h2>
        <div class="desc">{{ total.done }}/{{ total.all }} 完成 — 扫描自动标记</div>
      </div>
      <div style="display:flex; gap:10px">
        <button class="btn diag" :disabled="store.diagScanning" @click="autoScan()">🔬 自动扫描</button>
        <button class="btn" @click="store.resetChecklist()">↩ 重置</button>
      </div>
    </div>

    <div class="card" style="margin-bottom:16px">
      <div style="display:flex; justify-content:space-between">
        <span>完成进度</span><span>{{ total.pct }}%</span>
      </div>
      <div class="progress-line"><span :style="{ width: total.pct + '%' }"></span></div>
    </div>

    <div v-for="cat in store.checklist" :key="cat.id" class="checklist-cat">
      <div class="cat-head" @click="toggleCat(cat.id)">
        <span>{{ cat.icon }}</span>
        <strong>{{ cat.title }}</strong>
        <span class="count">{{ catDone(cat) }}/{{ cat.items.length }}</span>
        <span>{{ expanded[cat.id] === false ? '▶' : '▼' }}</span>
      </div>

      <div v-show="expanded[cat.id] !== false" class="card" style="border-radius:0 0 8px 8px; margin-top:-2px">
        <div v-for="it in cat.items" :key="it.id" class="check-item">
          <span class="checkbox" :class="{ done: store.checkState[it.id] }" @click="store.toggleCheck(it.id)">
            {{ store.checkState[it.id] ? '✓' : '' }}
          </span>
          <span>{{ it.text }}</span>
          <span v-if="it.important" class="tag-important">❗ 重要</span>
        </div>

        <div class="code-block">
          <span>💻 {{ cat.cmd }}</span>
          <span style="cursor:pointer" @click="copyCmd(cat.cmd)">📋</span>
        </div>
      </div>
    </div>
  </div>
</template>
