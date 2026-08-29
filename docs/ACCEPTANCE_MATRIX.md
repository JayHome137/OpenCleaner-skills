# OpenCleaner 1.2.0 验收矩阵

> 验证日期：2026-08-29
> 当前基线：1.2.0 公共发布后的 main
> 边界：实现与验证只使用脱敏测试数据、系统临时目录和只读本机扫描；没有操作用户真实文件。

## 结论

P0/P1 安全加固及 P2 资源限制已完成：`122` 项测试全部通过，覆盖全路径符号链接拒绝、Trash 原子 staging、review token 回收、日志轮转和请求限流。Windows 公开入口保持关闭，所有者工具内容只展示说明，不提供删除入口。

## 验收结果

| 验收项 | 状态 | 证据与边界 |
| --- | --- | --- |
| Skill 形态 | 通过 | 保留 `open-cleaner/SKILL.md`、Agent 元数据和标准包结构；产品形态仍是 macOS 存储分析 Skill。 |
| 包结构与契约 | 通过 | `python3 scripts/validate_package.py` 通过；scan、analysis、action-plan 使用 `1.1` schema，并验证 `1.0` 输入迁移。 |
| 单元与安全回归 | 本地通过 | `python3 -m unittest discover -s tests -p 'test_*.py' -q`：`122/122` 通过。除既有覆盖外，包含主目录外符号链接父路径、Trash staging、令牌回收、日志轮转和请求限流。 |
| 依赖无关安全门 | 本地通过 | `python3 scripts/security_scan.py`：检查永久删除、shell/eval/exec 表面和运行时语法；这是 CI 绊线，不替代人工审计。 |
| Dry Run 边界 | 通过 | Dry Run 明确标记 `purpose=dry-run`、`dry_run=true`；服务端和文件操作内核均拒绝把 Dry Run 当作执行会话。 |
| 决策闭环 | 本地通过 | 首页按 action plan 展示“扫描发现 / 当前可行动 / 当前被阻止”；真实本机计划为 `trash=0`、`reviewed_trash=10`、`open=105`、阻止 `25`。 |
| 所有者工具边界 | 本地通过 | npm、pnpm、Gradle、Go、Codex、Claude、Xcode DerivedData 等目标只显示归属、原因和建议命令，不生成 Trash action。 |
| 扫描缓存与进度 | 本地通过 | 私有版本化缓存、直接子项指纹、短 TTL、原子发布、`--progress`/`--no-cache`/`--cache-dir` 和取消语义均有测试；无错误 fixture 首扫 `misses=2` 且 `published=true`、二扫 `hits=2`/`misses=0`、结果哈希一致，状态目录 `0700`、文件 `0600`。 |
| 覆盖与 APFS 诊断 | 本地通过 | 报告展示完整/可用于初筛/关键区域缺失等级，以及 purgeable、废纸篓、快照、open-unlinked file 的只读解释和重扫建议。 |
| 双入口交付 | 本地通过 | `summarize.py` 生成聊天摘要；静态与受控 HTML 都嵌入决策数据，完整明细默认折叠；HTML 是只读证据入口，受控页面承接剩余交互。 |
| 文件操作边界 | 本地通过 | 仅允许 `open`、绿灯 `trash`、黄灯 `reviewed_trash`；目标先在同一父目录原子改名到私有 staging，再交给 Trash，没有永久删除回退。副作用前要求日志可写、整批重验和原路径复核。 |
| 项目生成目录阶段 | 本地通过 | 仅发现 allowlist 生成目录；要求项目清单、Git ignored/untracked、发布产物排除、30 分钟静置、打开文件检查、当前用户、黄灯令牌和执行前重验。 |
| 目录浏览与本地设置 | 本地通过 | 登记根内支持逐层进入、返回、搜索、名称/大小/时间排序、大小筛选和多选保护；设置文件 `0600`、状态目录 `0700`，拒绝 symlink 和越界根。 |
| 安装包与 App 归属 | 本地通过 | DMG/PKG/ISO/XIP/ZIP 专项视图，以及 Bundle ID、显示名、容器、缓存、Application Support、登录项和后台项关系进入版本化 analysis。 |
| 扩展运行态保护 | 本地通过 | SQLite WAL/SHM、打开文件、共享 Bundle ID、多版本 App、持久保护路径/App、活动进程和未知状态均在服务端执行前失败关闭。 |
| macOS 端到端 | 本地与远端通过 | `python3 tests/macos_smoke.py` 输出 `MACOS_SMOKE_OK`；Trash 只处理临时 HOME fixture。最近基线 [macOS run 33257420171](https://github.com/JayHome137/OpenCleaner-skills/actions/runs/33257420171) 通过。 |
| Windows 公开入口 | 关闭并失败关闭 | 规则归一化、公开扫描、分类、action-plan 契约和文件操作均拒绝 Windows；自动公开入口未恢复。 |
| Windows 实验资产 | 保留、未验证 | Windows helper、规则、参考文档和 `tests/windows_smoke.py` 留待独立测试；历史 [run 32550508708](https://github.com/JayHome137/OpenCleaner-skills/actions/runs/32550508708) 不代表当前版本。 |
| 扫描确定性 | 通过 | 当前 macOS-only benchmark 的 1 worker 与 4 workers 输出相同 SHA-256：`8f21768b6b8ce22a0c26ee6743df17e1678a26eb588896c7a3c4885ef6b1bb12`；耗时仅作本机回归参考。 |
| 报告内容与布局 | 本地通过 | 真实浏览器检查 `1440x900`、`390x844` 无横向溢出和控制台错误；首屏顺序为当前决策、受控会话、磁盘总览、所有者聚合、覆盖/APFS。 |
| 报告动作协议 | 本地通过 | 浏览器只提交 action ID；黄灯额外提交服务端签发的复核 token。静态报告 `SESSION=null`、无可执行批量操作控件；受控页黄灯确认未勾选前保持禁用。 |
| 本地授权模式 | main 已通过，实验分支独立保留 | main 默认 `token`；`codex/local-auth-modes` 提供 `system-confirm` 和 `view-only` 选择，但不合并、不作为默认 Release 能力。 |
| 操作结果呈现 | 本地通过 | 报告支持绿灯多选、批次确认、逐项历史、原路径复核、磁盘空间变化和真实重扫；目录浏览明确声明“只读浏览，不会授予删除权限”。 |
| 本机真实报告对账 | 本地通过但有覆盖缺口 | 两次只读扫描均为 `25` 个根请求、`24` 个完成、`1` 个跳过，调度 `3,167` 个路径、报告 `130` 项、`23` 个错误（`22` 权限拒绝 + `1` 缺失根）。Dry Run 两次均为 `115` 个计划动作、`25` 项阻止；缓存因扫描错误保持未发布。扫描 source hash 随实时字段变化是预期行为。两次 APFS open-unlinked 诊断分别为 `138/136` 个。临时验证产物仍保留，未删除用户数据。 |
| 实现独立性 | 通过（代码层） | 运行时代码、规则、契约、测试和报告不依赖 Mole 或原参考仓库主体；详见 `docs/INDEPENDENCE_AUDIT.md`。 |
| 第三方声明 | 通过 | `THIRD_PARTY_NOTICES.md` 和 `docs/PROVENANCE.md` 保留来源及既有 MIT 义务。 |
| 正式许可证 | 通过 | `1.2.0` 起采用官方 Apache License 2.0；`NOTICE` 和第三方 MIT 边界保持一致。 |
| 远端 CI | 通过 | main CI 已通过；矩阵覆盖 macOS 14/Python 3.9 与 macOS 15/Python 3.13，并包含归档解压自检。 |

## 真实本机 Dry Run 摘要

| 决策 | 数量 | 估算 |
| --- | ---: | ---: |
| 扫描发现绿灯 | 4 | `895,066,112 B`，约 `0.8 GiB` |
| 扫描发现黄灯 | 95 | `84,621,533,184 B`，约 `78.8 GiB` |
| 扫描发现红灯 | 31 | `19,241,160,704 B`，约 `17.9 GiB` |
| 当前普通 Trash | 0 | `0 B` |
| 当前黄灯人工复核 Trash | 10 | `2,040,692,736 B`，约 `1.9 GiB` |
| 当前只打开查看 | 105 | `94,358,310,912 B`，约 `87.9 GiB` |
| 当前被阻止 | 25 | `10,399,449,088 B`，约 `9.7 GiB` |

本机覆盖等级为“可用于初筛”（扫描根完成率 `96.0%`，权限拒绝 `22` 个）。APFS 只读诊断为：purgeable unavailable、废纸篓约 `32 MB`、本地快照 `1` 个、已删除但仍打开文件 `138` 个约 `0.5 GB`。这些都是解释性估算，不代表已经释放空间。

## 已确认的产品决策

1. 首要目标是准确解释并安全、可恢复地释放空间，而不是尽可能多删除。
2. npm、pnpm、Gradle、Go、Codex、Claude 等所有者工具内容只展示归属、为什么不能直接删和建议命令；Skill 不执行命令，也不开放删除入口。
3. 对话中的简短摘要与完整 HTML 同时保留：HTML 是最终只读证据和下钻入口，受控交互页面承接查看、复核和已授权操作。

## 本地复验命令

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -q
python3 scripts/validate_package.py
python3 scripts/benchmark_scan.py
python3 -m compileall -q open-cleaner/scripts tests scripts
python3 tests/macos_smoke.py
git diff --check
```

Windows 实验 smoke 当前不属于发行验证命令；恢复公开入口前必须另行完成原生 runner 与真实桌面测试。

## 后续候选（不阻塞 1.2.0）

- Full Disk Access 后的完整覆盖复扫体验；
- 更丰富的历史导出与两次扫描容量对比；
- 陌生目录 Agent 解释的证据质量测试；
- 安装包签名、挂载状态和唯一副本证据；
- 将项目阶段 gate 压缩为更易读的原因卡片。

这些候选都不授予新的删除权限，也不改变所有者工具只展示的决策。

## 许可边界

Apache-2.0 允许商业使用，但使用者仍需遵守许可证、NOTICE、第三方 notice 和商标边界。本记录不是法律意见。
