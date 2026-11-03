# 私有 fresh-runtime 安装链（开发验收，不是生产部署）

入口仍为 `tools/install/install.sh`，新增独立子命令 `fresh-local`。
旧 schema-1 安装器不变；不得把 schema-2 包传给旧路径。
当前仅支持显式 IPv4 回环地址、前台托管进程，不注册 systemd、不修改
路由/防火墙、不下载依赖。需要原生 Linux >=6.3、Python >=3.10、
MFD_EXEC、完整 memfd seals、procfs 和 pidfd。只读预检不等于实际执行成功。

每阶段先不带 `--confirm-plan` 查看计划；确认后重新执行同一命令并附
`--confirm-plan <完整 planHash>`。变更会使确认失效，工具不会替你确认。
安装目录和材料目录必须是同一可信父目录下两个不同的目录。

阶段如下（公共参数始终为 `--root ABS_INSTALL --materials ABS_MATERIALS`）：

1. `fresh-local install --bundle ABS_LOCAL_ZIP --bundle-sha256 TRUSTED_SHA256`
   仅安装严格校验的本地包，不启动服务。包哈希须通过可信渠道取得。
2. `fresh-local prepare --username NAME --namespace NAME --request-key KEY`
   必须显式选择 `--generate` 或 `--import-file ABS_PRIVATE_FILE`。
   材料文件包含明文管理 token 和 vault master，权限0700/0600；不要分享。
   初始节点凭证为空，不用默认 UUID，也不会静默重建丢失的密钥。
3. `fresh-local init-vault --request-key KEY`
   使用安装包内精确固定的 maintenance ELF，封印执行 `vault-init-bound`。
   这是一次性消费意图；不确定失败会保留状态，禁止自动重试/接管。
4. `fresh-local start --bind 127.0.0.1:PORT --origin http://127.0.0.1:PORT`
   封印执行专用 fresh runtime；显式启用同源真实 Web 资源和回环订阅交付。
   管理员从已保护的材料中取得 token 登录，再通过已确认 API 创建节点凭证、
   配置、应用并发布连接信息。HTTP ready 不代表所有协议或生产可用。
   本命令前台运行，Ctrl-C/SIGTERM 触发已拥有进程的停止，不接受任意 PID。
5. 已观察到第一次 HTTP ready 且正常停止后，`fresh-local restart` 配合相同
   bind/origin 和新的计划确认，只打开完全相同的已配对 artifact set。
6. 先停止前台服务，再 `fresh-local uninstall`。该动作在同一安装生命周期锁下
   **仅禁用这个本地配置，不是删除程序文件的完整卸载**。保留全部文件，
   包括可执行程序、Web资源、管理材料、数据库、vault、runtime和所有收据，
   删除文件数为0。程序文件删除是另一个明确确认的 `remove-program-files` 动作（见下文）；禁用收据明确命名为
   `profile-disabled-all-files-retained.json`。它不解除绑定或授权再次fresh/adopt。

`fresh-local status` 只返回文件观察和主机预检，绝不根据 PID 文件/收据猜测
服务仍在运行。升级、旧版本回退、恢复、admin-only reservation 接管均不可用。
更换 daemon/worker 会改变 artifact-set 绑定；当前没有跨 artifact-set 升级事务。

打包使用独立 `build_fresh_bundle.py`：所有 daemon/worker/maintenance 都必须
提供明确 SHA256；daemon descriptorVersion2 由封印执行的 `describe` 产生，
不是按文件名猜测。真实 Web build 来源必须单独核验并保留来源清单；测试
占位页面不构成可交付面板。Web 文件在包内逐个固定且启动前重新核验。

安全边界：可信且协作的同UID程序、稳定受信任路径、持久可信父目录。
不声称防御恶意同UID修改、SQLite路径竞争、物理断电、外部删除或历史回滚。
监督停止仅对直接子进程和已通过PPid/起始时钟/已加载ELF SHA/pidfd识别的
worker拥有处置权，不声称证明从未观测到的任意孤儿进程已消失。

## Separate explicit program-file removal (private profile)

`uninstall` remains deactivation only: it retains every executable, Web asset and
state file. To remove program files, first stop the foreground owner and perform
that explicit deactivation. On a runtime-ineligible host, use the separate
metadata-only `deactivate` path with the **original verified archive**; it shares
full inventory checks and all lifetime locks with removal, starts no process,
and adds only the existing disabled marker (zero deleted files):

```sh
./install.sh fresh-local deactivate --root /private/install \
  --materials /private/materials --bundle /private/original.zip \
  --bundle-sha256 TRUSTED_SHA256
# Inspect the plan; repeat with --confirm-plan EXACT_PLAN_HASH.
```

Then request the separate removal plan using the same original archive:

```sh
./install.sh fresh-local remove-program-files --root /private/install \
  --materials /private/materials --bundle /private/original.zip \
  --bundle-sha256 TRUSTED_SHA256
# Inspect the complete read-only plan; repeat with --confirm-plan EXACT_PLAN_HASH.
```

Both cleanup actions execute no archive member, start/kill no process, use no network,
and need no runtime kernel/architecture eligibility. Each acquires the installation,
materials and actual control/runtime/vault directory locks, so an orphan service
holding its own data-root lease blocks removal even when no supervisor remains.
A wholly absent materials root is allowed; an existing partial materials tree is
refused. Both current and historical disabled markers remain supported.

The original archive and installed manifest must match the installation record.
The bounded full inventory must contain exactly its expected regular single-link
files and derived directories, with exact hashes, inode identities and trusted
modes. Symlinks, hardlinks, unknown files or even unknown empty directories are
refused before intent. The action unlinks only manifest-listed release files and
removes only their empty directories. It retains `release/manifest.json`, every
pre-existing installation/provenance file, and all bootstrap/material/control/
vault/runtime files byte-for-byte. It does not remove the installation root,
deactivate host services, purge data, restore snapshots or reactivate anything.

`program-removal-intent.json` is bounded immutable metadata binding the confirmed
plan, archive/manifest/inventory digests and expected count. Its file and parent
fsync complete before the first unlink. Each unlink/rmdir has a parent fsync.
`program-removal-receipt.json` records the final observed absence; the command
reports success only after every durability barrier returns successfully.

**No resume or automatic retry is implemented.** Any intent consumes the action,
including cancellation, path changes and partial failures. Keep the evidence for
review; do not delete the intent or attempt reinstallation/adoption. A readable
receipt does not prove a previous fsync succeeded: status examines the live release
inventory and distinguishes `program_files_absent_observed` from
`incomplete_or_uncertain`, always marking prior durability `not_inferred`.
Cooperative same-UID tools and stable trusted paths are required; this is not
protection from a hostile same-UID actor or physical rollback.

New deactivation outputs use action-specific `removesProgramFiles:false`; global
status advertises the separate removal capability. Historical on-disk receipts
remain untouched and both disabled-marker names still block reactivation. Legacy
`uninstall` retains its old preflight; `deactivate` is the archive-bound cleanup
path for unsupported hosts. Runtime install/prepare/init/start gates are unchanged.
