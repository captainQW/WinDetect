<script setup>
const props = defineProps({
  icon: String,
  label: String,
  value: [Number, String],
  unit: { type: String, default: '' },
  pct: { type: Number, default: null }, // bar fill 0-100
  sub: String
})

function barColor(p) {
  if (p >= 85) return 'var(--red)'
  if (p >= 70) return 'var(--orange)'
  if (p >= 50) return 'var(--yellow)'
  return 'var(--accent)'
}
</script>

<template>
  <div class="metric">
    <div class="label">
      <span>{{ icon }} {{ label }}</span>
      <span>{{ value }}{{ unit }}</span>
    </div>
    <div class="value">{{ value }}{{ unit }}</div>
    <div v-if="pct !== null" class="bar">
      <span :style="{ width: Math.min(pct, 100) + '%', background: barColor(pct) }"></span>
    </div>
    <div v-if="sub" class="sub">{{ sub }}</div>
  </div>
</template>
