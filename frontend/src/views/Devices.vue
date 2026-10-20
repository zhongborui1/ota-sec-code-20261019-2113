<template>
  <div>
    <div class="card">
      <h2>设备列表（共 {{ data.count || 0 }} 台）</h2>
      <button class="btn" :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新' }}</button>
      <p v-if="error" class="fail">{{ error }}</p>
      <p>设备必须先离线预登记公钥，再通过私钥持有证明完成注册。</p>
      <table style="margin-top: 12px;">
        <tr>
          <th>VIN</th>
          <th>登记状态</th>
          <th>设备启用</th>
          <th>曾完成注册</th>
        </tr>
        <tr v-for="d in data.devices" :key="d.vin">
          <td class="mono">{{ d.vin }}</td>
          <td>已预登记公钥</td>
          <td><span :class="d.enabled ? 'ok' : 'fail'">{{ d.enabled ? '启用' : '停用' }}</span></td>
          <td>{{ d.enrolled ? '已完成 PoP' : '尚未注册' }}</td>
        </tr>
        <tr v-if="!loading && !error && !data.devices.length"><td colspan="4">暂无预登记设备</td></tr>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
const API = 'http://192.168.200.128:8080'
const data = ref({ count: 0, devices: [] })
const loading = ref(false)
const error = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    const response = await fetch(`${API}/admin/devices`)
    if (!response.ok) throw new Error(`设备接口返回 ${response.status}`)
    data.value = await response.json()
  } catch (e) {
    error.value = e.message || '设备列表加载失败'
  } finally {
    loading.value = false
  }
}
onMounted(load)
</script>
