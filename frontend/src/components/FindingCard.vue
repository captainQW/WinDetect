<script setup>
defineProps({ finding: Object })

const sevNames = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', ok: '正常'
}
const sevIcons = {
  critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', ok: '✅'
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
    <div class="f-fix">💡 {{ finding.fix }}</div>
  </div>
</template>
