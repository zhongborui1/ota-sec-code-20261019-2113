<template>
  <div>
    <div class="card">
      <h2>系统健康</h2>
      <button class="btn" @click="load">刷新</button>
      <table style="margin-top: 12px;">
        <tr><th>指标</th><th>值</th></tr>
        <tr><td>状态</td><td><span :class="health.status === 'ok' ? 'ok' : 'fail'">{{ health.status }}</span></td></tr>
        <tr><td>Active 签名密钥</td><td class="mono">{{ health.active_key_id }}</td></tr>
        <tr><td>Redis</td><td><span :class="health.redis_ok ? 'ok' : 'fail'">{{ health.redis_ok ? '✓' : '✗' }}</span></td></tr>
        <tr><td>MinIO</td><td><span :class="health.minio_ok ? 'ok' : 'fail'">{{ health.minio_ok ? '✓' : '✗' }}</span></td></tr>
        <tr><td>Payload 一致性</td><td><span :class="health.payload_consistency && health.payload_consistency.ok ? 'ok' : 'fail'">{{ health.payload_consistency && health.payload_consistency.ok ? '✓ 一致' : '✗' }}</span></td></tr>
        <tr><td>存储后端</td><td>{{ health.storage_backend }}</td></tr>
      </table>
    </div>

    <div class="card">
      <h2>密钥池概览</h2>
      <table>
        <tr><th>指标</th><th>值</th></tr>
        <tr><td>签名密钥（active）</td><td>{{ summary.trust_status_count?.active || 0 }}</td></tr>
        <tr><td>签名密钥（deprecated）</td><td>{{ summary.trust_status_count?.deprecated || 0 }}</td></tr>
        <tr><td>签名密钥（prepared）</td><td>{{ summary.trust_status_count?.prepared || 0 }}</td></tr>
        <tr><td>签名密钥（revoked）</td><td>{{ summary.trust_status_count?.revoked || 0 }}</td></tr>
        <tr><td>ECU 密钥池（服务端公钥）</td><td>{{ summary.ecu_pool_size || 0 }}</td></tr>
        <tr><td>ECU 本地密钥（车辆）</td><td>{{ summary.ecu_local_size || 0 }}</td></tr>
      </table>
    </div>

    <div class="card">
      <h2>审计统计</h2>
      <p>总记录：<b>{{ summary.audit?.total || 0 }}</b></p>
      <table v-if="summary.audit?.by_action?.length">
        <tr><th>Action</th><th>Result</th><th>Count</th></tr>
        <tr v-for="r in summary.audit.by_action" :key="r.action + r.result">
          <td class="mono">{{ r.action }}</td>
          <td>{{ r.result }}</td>
          <td>{{ r.count }}</td>
        </tr>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

const API = 'http://192.168.200.128:8080'
const health = ref({})
const summary = ref({})

async function load() {
  health.value = await (await fetch(`${API}/health`)).json()
  summary.value = await (await fetch(`${API}/admin/summary`)).json()
}

onMounted(load)
</script>
