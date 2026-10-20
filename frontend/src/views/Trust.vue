<template>
  <div>
    <div class="card">
      <h2>信任元数据（共 {{ keys.length }} 把签名密钥）</h2>
      <button class="btn" @click="load">刷新</button>
      <p style="margin-top: 8px; color: #666;">根签名策略版本：{{ trust.version }}（根公钥保持预置）</p>
      <p>密钥状态由离线签发的策略授权，轮换需使用 scripts/17-security-admin.py。</p>
      <table style="margin-top: 12px;">
        <tr>
          <th>Key ID</th>
          <th>状态</th>
          <th>生效时间</th>
          <th>失效时间</th>
        </tr>
        <tr v-for="k in keys" :key="k.key_id">
          <td class="mono">{{ k.key_id }}</td>
          <td><span class="badge" :class="'badge-' + k.status">{{ k.status }}</span></td>
          <td class="mono">{{ k.not_before }}</td>
          <td class="mono">{{ k.not_after }}</td>
        </tr>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
const API = 'http://192.168.200.128:8080'
const trust = ref({})

const keys = computed(() => {
  if (!trust.value.keys) return []
  return Object.entries(trust.value.keys).map(([kid, info]) => ({
    key_id: kid,
    status: info.status,
    not_before: (info.not_before || '').slice(0, 19).replace('T', ' '),
    not_after: (info.not_after || '').slice(0, 19).replace('T', ' '),
  }))
})

async function load() {
  trust.value = await (await fetch(`${API}/trust-metadata`)).json()
}
onMounted(load)
</script>
