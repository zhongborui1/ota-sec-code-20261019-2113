# 四项安全修复与 Ubuntu 保留数据迁移

本次修改针对 `ota-sec-code-20261019-2113`，不是早期 `OTA_server` 工程。现有根密钥、车辆私钥、固件、回滚计数和测试证据均不由回归测试修改。首次升级需要完成下面的配置迁移，不能只替换 Python 文件后直接使用旧的无签名策略。

## 1. 修复了什么

| 问题 | 现在的行为 | 主要文件 |
| --- | --- | --- |
| 网络返回的公钥可被直接信任 | 根私钥离线签署策略；API、签名服务、ECU 独立验证；SQLite 持久化最高版本，拒绝回退、同版本改内容、公钥换绑、撤销后再启用、延长旧密钥宽限期 | `services/ota_common/trust.py`、`scripts/17-security-admin.py` |
| 可改元数据跳过启动验签 | 每次启动验证签名清单及实际固件 SM3，`signature_verified` 和 `provenance` 不再作为授权依据；出厂基线也必须由根签名批准；检查持久化防回滚下限 | `services/vehicle-sim/installer.py`、`boot_agent.py` |
| 任意 VIN/公钥可注册，错误 PoP 会破坏已有公钥 | 离线预登记 VIN 与公钥；在线只验证一次性挑战及私钥持有证明；服务器只读登记，不持有 ECU 私钥；失败不覆盖、不删除合法身份 | `services/ota-api/app.py`、`services/signing-service/app.py` |
| 报告缺字段或存储故障仍放行 | 强制 VIN/任务/固件绑定、nonce、sequence、时间窗；PostgreSQL 同一事务完成去重、状态转换、审计；失败整体回滚，服务返回 503；冲突返回 409 | `services/ota_common/reports.py`、`data/postgres-init/03-report-security.sql` |

正常报告状态为 `issued → PENDING_REBOOT → CONFIRMED / ROLLED_BACK / FAILED`，也允许下载或安装阶段 `issued → FAILED`。不能直接把 `issued` 上报为 `CONFIRMED`。设备 Token 在 Redis 中按 SHA-256 后的索引存储；旧缓存 Token 首次返回 401 时，车端会重新完成 PoP 注册。

## 2. 在 Ubuntu 上先备份、检查

以下命令均从 Ubuntu 上**本项目根目录**执行。先停止正在运行的模拟车，再停止两个写入服务；不要运行 `docker compose down -v`。

```bash
docker compose -f compose/docker-compose.yml -f compose/docker-compose.override.yml stop ota-api signing-service
stamp=$(date +%Y%m%d-%H%M%S)
tar -czf "../ota-security-backup-${stamp}.tgz" pki data compose
docker exec ota-postgres sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > "../ota-postgres-${stamp}.sql"
```

备份包含私钥，应保存在受控位置。若某目录或容器在你的部署中尚不存在，先按已有初始化流程建立环境，再完成本页新增配置；不要用新根密钥覆盖已有根。

只查看现有策略状态，不输出口令或私钥：

```bash
python3 - <<'PY'
import json
from pathlib import Path
doc = json.loads(Path('data/trust/trust-metadata.json').read_text())
p = doc.get('signed', doc)
print('signed:', 'signed' in doc, 'version:', p.get('version', p.get('trust_anchor_version')))
for kid, info in p['keys'].items():
    print(kid, info['status'], info.get('revoke_at', ''))
PY
```

确认已有 `pki/root/root.key`、`root.pub` 和 `pki/.secrets/root.pass` 是正确的一组。`gmssl` 必须在 PATH 中。根公钥预置到车端属于可信初始化，不能从未经验证的网络响应自动替换。

## 3. 给现有信任策略加根签名

使用管理员主机上的离线工具。`--root` 若需使用，放在子命令 `policy/provision/factory` **之前**；不指定则使用脚本所在项目。

如果当前实际状态是 **v1 已撤销、v2 使用中**，首次迁移示例为：

```bash
python3 scripts/17-security-admin.py policy --migrate-unsigned \
  --key ota-signing-v1=revoked --key ota-signing-v2=active
```

只有当前确实是 **v1 使用中、v2 尚未启用**，才使用：

```bash
python3 scripts/17-security-admin.py policy --migrate-unsigned \
  --key ota-signing-v1=active --key ota-signing-v2=prepared
```

两段命令是不同环境的示例，**不要依次执行**。其他状态、更多密钥都应按审核后的实际状态逐项传入 `--key`，尤其不能把旧的 revoked 改回 active。无签名旧策略没有可信来源，因此首次迁移要求管理员显式审核；工具无法替你判断旧文件是否已被篡改。

已迁移到根签名策略后，续发通常只需：

```bash
python3 scripts/17-security-admin.py policy --hours 168
```

默认策略有效期 7 天，到期前应续发。续发使版本递增，保留密钥状态；不需要再次 `--migrate-unsigned`。策略过期时拒绝新升级，已确认的合法分区仍可离线验签启动。

工具会预置/核对 `pki/vehicle-trust/root.pub`；发现与当前根公钥不一致就停止。不要删除 `publisher-state.sqlite3`、API/签名服务的 `trust-state.sqlite3` 或各车 `trust.sqlite3`，这些是防回退记录，必须与数据一起保留和备份。撤销生效按签名中的 `revoke_at` 判断，不依赖清理线程。

## 4. 预登记车辆公钥

已有模拟车辆使用 `pki/ecu-local/<VIN>/ecu.key`，保留原密钥并批准现有身份：

```bash
python3 scripts/17-security-admin.py provision --count 100 --start 0 --approve-existing
```

对应 VIN 为 `LSVAM4187C2000000` 至 `LSVAM4187C2000099`。单车使用：

```bash
python3 scripts/17-security-admin.py provision --vin LSVAM4187C2000000 --approve-existing
```

新车没有本地密钥时可省略 `--approve-existing`，工具在车端目录生成密钥；已有密钥时工具会检验私钥、公钥是否成对，不覆盖已登记的不同公钥，也不重新启用已禁用设备。原先仅在 `ecu-pool` 的身份不会自动导入，应明确审核并迁移成对应车辆的本地身份，不能依靠服务器密钥池兜底。

服务器仅挂载 `pki/device-registry` 公钥登记目录，API/签名服务均不挂载 `ecu-local`、`ecu-pool` 和 `ecu-demo`。前端设备页同步改为显示预登记、启用和曾完成 PoP 的状态；“曾注册”不代表当前在线或 Token 仍有效。

## 5. 显式批准可信出厂基线

旧实现曾从下载的固件自动构造出厂基线，这一行为已取消。先人工确认原始出厂固件、版本号和 rollback index，**不要从可改的旧 meta.json 直接照抄并自动批准**。

如果审核确认已有 `data/vehicle-state/_factory/payload.bin` 就是可信旧固件，例如真实版本 `2.3.0`、真实 rollback index `11`，执行：

```bash
python3 scripts/17-security-admin.py factory \
  --file data/vehicle-state/_factory/payload.bin --version 2.3.0 --rollback-index 11
```

若是全新环境，用已审核固件的真实路径作为 `--file`，工具会复制到 `_factory/payload.bin`。版本和 index 必须与该固件实际发布信息一致。已存在 `factory.json` 时拒绝覆盖；不应通过删除它来绕过检查。现有各车正常分区、回滚计数不需清空；缺少合法签名清单的历史非出厂分区不能直接作为可信 OTA 镜像，需另行审核恢复。

## 6. 迁移 PostgreSQL，重建容器

已有数据库卷不会再次自动执行 `docker-entrypoint-initdb.d`。显式运行新增 SQL（可重复执行，不删除旧数据）：

```bash
docker exec -i ota-postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < data/postgres-init/03-report-security.sql

docker compose -f compose/docker-compose.yml -f compose/docker-compose.override.yml config --quiet
docker compose -f compose/docker-compose.yml -f compose/docker-compose.override.yml up -d --build
docker compose -f compose/docker-compose.yml -f compose/docker-compose.override.yml logs --tail 80 ota-api signing-service
```

使用与你原部署相同的 Compose 环境变量配置。API 与签名服务的构建 context 已改为 `services`，包含共享安全模块；API 镜像新增 GmSSL，以便独立验证根签名。不要继续使用旧镜像而只复制一个 app.py。

签名容器使用 UID/GID `1000:1000`。保持原来对签名私钥、口令文件、服务身份文件和 `data/signing-auth` 的最小读取/写入权限；新策略和公钥登记文件由工具设为公开可读。遇到 Permission denied 应逐项核对这些文件的属主/ACL，不能对整个 `pki` 执行 `chmod -R 777`。根私钥和 release 私钥不挂载进在线容器。

## 7. 恢复发布与模拟升级

为当前 active 签名密钥重新签发发布授权，下面以 v2 为例；若实际 active 不是 v2，替换成实际密钥 ID：

```bash
python3 scripts/15-release-authorize.py issue --key-id ota-signing-v2 --max-tasks 2000 --validity-hours 6
curl -f http://127.0.0.1:8080/trust-metadata
python3 services/vehicle-sim/simulator.py 1
```

确保固件包和模板已按现有流程构建、上传，清单尚未过期且 rollback index 不低于已提交版本。旧的无完整防重放字段报告会被拒绝；迁移前未完成的升级应重新申请任务，不能靠修改历史报告补成成功。

先确认一车报告 `PENDING_REBOOT`、独立启动自检、`CONFIRMED` 全部成功，再在验收环境执行：

```bash
python3 services/vehicle-sim/simulator.py 100
```

这是真实完整升级，会写车端分区、任务和报告；100 MB × 100 车还需预留下载与分区空间，建议至少 30 GB 空闲空间。是否达到 100/100 必须以本次新产生的 `evidence/raw/full-upgrade-100-*.json` 为准，不能复用历史成功率。旧的独立 `ab-recovery-test.py` 不作为修复后验收依据，应使用实际 `installer.py/boot_agent.py` 路径及本次回归测试。

## 8. 以后如何轮换

仅在 v1 active、v2 prepared 的环境中：

```bash
python3 scripts/17-security-admin.py policy \
  --key ota-signing-v1=deprecated --key ota-signing-v2=active --grace-seconds 60
python3 scripts/15-release-authorize.py issue --key-id ota-signing-v2 --max-tasks 2000 --validity-hours 6
```

60 秒后在线请求会把 v1 视为 revoked；需要持久记录显式撤销时再发布 `policy --key ota-signing-v1=revoked`。不能延长已有宽限期。全新 v1→v2 轮换演练使用隔离部署，不把正式已撤销状态重置回 v1。旧在线 `/admin/rotate-trust` 返回 `409 offline_signed_policy_required`，`scripts/continuous` 的旧自动改策略入口已停止使用。

“5 分钟生效”只适用于能够及时获得新策略的在线设备；该模拟器在验清单和安装前刷新策略，启动进程离线验证最后可信策略。断网 ECU 不会凭空收到撤销通知。本次未实现**根公钥本身的在线轮换**，实现的是固定可信根下的发布密钥轮换及防回退。

## 9. 本次测试与边界

测试入口和 PostgreSQL 集成测试说明见 `tests/README.md`。

本机使用真实 GmSSL 完成正常签名、恶意签名、策略持久化和独立启动进程测试；HTTP 用例对 Redis/PostgreSQL/MinIO 使用显式传输替身。Windows 对签名服务的 POSIX 审计文件锁使用测试替身，未声称验证 Ubuntu 的 flock。真实 PostgreSQL 事务测试需要单独测试库，本机未执行；Docker 构建和 100 车完整验收也必须在 Ubuntu 重跑。

本项目仍是软件仿真：本地状态不等于 TPM/HSM，模拟车口令不应当作生产凭据方案，HTTP Bearer 传输也不等于生产 mTLS。不能声称已完成硬件安全启动、物理攻击防护或根锚安全恢复机制。
