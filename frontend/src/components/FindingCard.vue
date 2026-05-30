<script setup>
import { ref } from 'vue'

defineProps({ finding: Object })

const sevNames = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', ok: '正常'
}
const sevIcons = {
  critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', ok: '✅'
}

const copied = ref(false)
function copyCmd(cmd) {
  navigator.clipboard?.writeText(cmd).then(() => {
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  })
}
</script>

<template>
  <div class="finding" :class="finding.sev">
    <div class="f-title">
      <span class="sev" :class="finding.sev">
        {{ sevIcons[finding.sev] || '⚠️' }} {{ sevNames[finding.sev] || finding.sev }}
      </span>
      &nbsp;{{ finding.desc }}
    </div>
    <div v-if="finding.detail" class="f-detail">{{ finding.detail }}</div>

    <!-- Detailed, ordered remediation steps -->
    <div v-if="finding.steps && finding.steps.length" class="f-solution">
      <div class="f-solution-head">🛠️ 解决方法</div>
      <ol class="f-steps">
        <li v-for="(s,i) in finding.steps" :key="i">{{ s }}</li>
      </ol>
    </div>
    <!-- Fallback to the short fix when no detailed steps are provided -->
    <div v-else-if="finding.fix" class="f-fix">💡 {{ finding.fix }}</div>

    <!-- Ready-to-run command -->
    <div v-if="finding.cmd" class="f-cmd">
      <code>{{ finding.cmd }}</code>
      <button class="f-copy" @click="copyCmd(finding.cmd)">{{ copied ? '已复制' : '复制' }}</button>
    </div>

    <div v-if="finding.ref" class="f-ref">ℹ️ {{ finding.ref }}</div>
  </div>
</template>

<style scoped>
.f-solution { margin-top: 10px; }
.f-solution-head { font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 6px; }
.f-steps { margin: 0; padding-left: 20px; }
.f-steps li { font-size: 13px; line-height: 1.7; color: var(--text-dim); }
.f-cmd {
  display: flex; align-items: center; gap: 8px;
  margin-top: 10px; padding: 8px 10px;
  background: rgba(0,0,0,.28); border: 1px solid var(--border); border-radius: 6px;
  font-family: "Consolas","Cascadia Code",monospace;
}
.f-cmd code { flex: 1; font-size: 12.5px; color: #7dd3fc; white-space: pre-wrap; word-break: break-all; }
.f-copy {
  flex-shrink: 0; cursor: pointer; font-size: 12px;
  padding: 3px 10px; border-radius: 4px;
  border: 1px solid var(--border); background: var(--card); color: var(--text);
}
.f-copy:hover { background: var(--accent); color: #fff; }
.f-ref { margin-top: 8px; font-size: 12px; color: var(--text-dim); }
</style>
