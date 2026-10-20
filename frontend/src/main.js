import { createApp } from 'vue'
import { createRouter, createWebHashHistory } from 'vue-router'
import App from './App.vue'
import Dashboard from './views/Dashboard.vue'
import Devices from './views/Devices.vue'
import Trust from './views/Trust.vue'

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', component: Dashboard },
    { path: '/devices', component: Devices },
    { path: '/trust', component: Trust },
  ],
})

createApp(App).use(router).mount('#app')
