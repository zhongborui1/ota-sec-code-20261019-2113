<template>
  <div class="app">
    <header>
      <h1>OTA 安全升级系统 — 管理后台</h1>
      <nav>
        <router-link to="/">概览</router-link>
        <router-link to="/devices">设备</router-link>
        <router-link to="/trust">信任元数据</router-link>
      </nav>
    </header>
    <main>
      <router-view />
    </main>
  </div>
</template>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background: #f5f7fa; color: #333; }
.app { max-width: 1200px; margin: 0 auto; padding: 20px; }
header { background: #1e293b; color: #fff; padding: 16px 24px; border-radius: 8px; margin-bottom: 20px; }
header h1 { font-size: 20px; margin-bottom: 12px; }
nav a { color: #cbd5e1; text-decoration: none; margin-right: 20px; padding: 6px 12px; border-radius: 4px; }
nav a:hover { background: #334155; color: #fff; }
nav a.router-link-active { background: #3b82f6; color: #fff; }
main { background: #fff; padding: 24px; border-radius: 8px; min-height: 500px; }
.card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.card h2 { font-size: 16px; margin-bottom: 12px; color: #1e293b; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
th { background: #f1f5f9; font-weight: 600; }
.ok { color: #16a34a; font-weight: 600; }
.fail { color: #dc2626; font-weight: 600; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.badge-active { background: #dcfce7; color: #15803d; }
.badge-deprecated { background: #fef3c7; color: #b45309; }
.badge-prepared { background: #dbeafe; color: #1d4ed8; }
.badge-revoked { background: #fee2e2; color: #b91c1c; }
.btn { padding: 6px 14px; background: #3b82f6; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
.btn:hover { background: #2563eb; }
.mono { font-family: monospace; font-size: 12px; }
</style>
