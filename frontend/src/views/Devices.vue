<template>
  <div>
    <div class="card">
      <h2>设备列表（共 {{ data.count || 0 }} 台）</h2>
      <button class="btn" @click="load">刷新</button>
      <table style="margin-top: 12px;">
        <tr>
          <th>VIN</th>
          <th>车辆私钥</th>
          <th>Token</th>
          <th>服务端公钥</th>
          <th>服务端私钥</th>
          <th>已注册</th>
        </tr>
        <tr v-for="d in data.devices" :key="d.vin">
          <td class="mono">{{ d.vin }}</td>
          <td><span :class="d.has_local_key ? 'ok' : 'fail'">{{ d.has_local_key ? '✓' : '✗' }}</span></td>
          <td><span :class="d.has_token ? 'ok' : 'fail'">{{ d.has_token ? '✓' : '✗' }}</span></td>
          <td><span :class="d.has_server_pub ? 'ok' : 'fail'">{{ d.has_server_pub ? '✓' : '✗' }}</span></td>
          <td><span :class="d.has_server_key ? 'fail' : 'ok'">{{ d.has_server_key ? '⚠ 存在' : '✓ 无' }}</span></td>
          <td><span :class="d.enrolled ? 'ok' : 'fail'">{{ d.enrolled ? '✓ PoP' : '✗' }}</span></td>
        </tr>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
const API = 'http://192.168.200.128:8080'
const data = ref({ count: 0, devices: [] })

async function load() {
  data.value = await (await fetch(`${API}/admin/devices`)).json()
}
onMounted(load)
</script>
