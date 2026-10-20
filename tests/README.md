# 四项安全修复回归测试

从项目根目录执行。要求 Python 3.10+、PATH 中有真实 GmSSL、Python 环境已安装 Flask。本组测试使用临时目录、临时密钥和临时固件，不连接正常服务、不改正常车辆数据、不修改已发布策略。

```bash
python3 -m unittest discover -s tests -v
```

包含策略根签名/防回退/撤销、真实 SM2 PoP、公钥替换和错误注册拒绝、独立启动进程、固件与元数据篡改、失败回滚、报告字段校验、故障拒绝、离线管理工具。GmSSL 缺失会报错，不使用伪验签替代。

HTTP 测试对 Redis、PostgreSQL 和 MinIO 使用显式传输替身，只证明接口校验和故障行为，不代表真实数据库事务已经通过。测试故意触发数据库故障时会出现日志异常栈，这是预期场景；以 unittest 最终结果为准。

## 真实 PostgreSQL 事务测试

Ubuntu 上准备一个**独立测试数据库**及可建 schema 的测试用户。不要填正式 OTA 数据库地址。环境需安装 `psycopg2-binary`。

```bash
export OTA_TEST_DATABASE_URL='postgresql://测试用户:测试口令@127.0.0.1:5432/ota_security_test'
python3 -m unittest discover -s tests -p test_reports_postgres.py -v
unset OTA_TEST_DATABASE_URL
```

每个用例创建并清理独立 UUID schema。测试正常 pending→confirmed、拒绝跳过 pending、nonce 重放、sequence 回退、并发终态互斥、审计失败时整个事务回滚。连接失败或缺驱动会报错，不会记成通过；未设置 URL 时明确显示 6 项 skipped。

Docker、MinIO、Redis、网络和 100 车完整升级属于部署验收，按 `docs/02-security-migration.md` 在 Ubuntu 完成；本组小固件回归结果不能替代 100 MB 性能或 100 车完整升级证据。
