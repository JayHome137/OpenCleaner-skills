# 1.0.0 验收矩阵

> 验证日期：2026-08-23
> 边界：只操作仓库内测试数据和系统临时目录，不操作用户真实文件；远程 runner 状态以 GitHub Actions 为准。

## 结论

既有 1.0.0 名称同步提交 `9cf09d79533c10ba65a729120bc52bac753263d4` 曾在真实 macOS 与 Windows runner 上完成验证。本轮 HTML 受控处置三阶段及 macOS-only 收口在本地验证；Windows 公开入口已经关闭，历史 Windows runner 只作来源记录，不代表当前支持。当前工作树仍未提交、未推送。

## 验收结果

| 验收项 | 状态 | 证据与边界 |
| --- | --- | --- |
| Skill 形态 | 通过 | 保留 `open-cleaner/SKILL.md`、Agent 元数据和标准包结构；未改造成终端套件。 |
| 包结构与契约 | 通过 | `python3 scripts/validate_package.py`；scan、analysis、action-plan schema 均受验证。 |
| 单元与安全回归 | 本地通过 | 87 个测试通过；新增覆盖运行态 active/unknown、计划后进程启动、黄绿 mode 隔离、下载/临时直接子项、项目生成目录、最短静置期、所有权、短时一次性令牌、错配/过期/重放/混批、真实重扫、任意路径注入和 Windows 全入口失败关闭。 |
| Dry Run 边界 | 通过 | Dry Run 具有显式 purpose，服务端和文件操作内核均拒绝执行。 |
| 文件操作边界 | 本地通过 | 仅允许 `open`、绿灯 `trash`、黄灯 `reviewed_trash`；两个变更 mode 都使用同一 Trash 内核且没有永久删除回退。副作用前要求日志可写并完整复核整批目标。 |
| 项目生成目录阶段 | 本地通过 | 仅发现 allowlist 生成目录；要求项目清单、Git ignored/untracked、发布产物排除、30 分钟静置、打开文件检查、当前用户、黄灯令牌和执行前重验，重新扫描保持项目阶段。 |
| macOS 端到端 | 本地通过 | 当前工作树 `python3 tests/macos_smoke.py` 输出 `MACOS_SMOKE_OK`；既有版本的 [macOS run 32550508546](https://github.com/JayHome137/OpenCleaner-skills/actions/runs/32550508546) 也通过。两者都只处理临时 HOME fixture。 |
| Windows 公开入口 | 关闭并失败关闭 | 规则归一化、公开扫描、分类、action-plan 契约和文件操作均拒绝 Windows；自动 workflow 入口已移除。 |
| Windows 实验资产 | 保留、未验证 | Windows 扫描 helper、规则、参考文档和 `tests/windows_smoke.py` 留待后续独立测试；[历史 run 32550508708](https://github.com/JayHome137/OpenCleaner-skills/actions/runs/32550508708) 不代表当前版本。 |
| 扫描确定性 | 通过 | 当前 macOS-only benchmark 的 1 worker 与 4 workers 输出相同 SHA-256：`8f21768b6b8ce22a0c26ee6743df17e1678a26eb588896c7a3c4885ef6b1bb12`。 |
| 报告内容与布局 | 本地通过 | 临时交互报告和 129 项真实静态报告均完成 1440×900、390×844 浏览器验证；无页面横向位移、控件重叠或控制台错误。移动端 Top 5 保留排名、级别、大小和项目列。 |
| 报告动作协议 | 本地通过 | 浏览器仅提交 action ID；黄灯额外提交服务端签发的复核 token。无 `data-paths`、`authorizedPaths` 或客户端 mode/path 输入；静态报告为 `SESSION = null` 且有 0 个动作控件。 |
| 操作结果呈现 | 本地通过 | 报告支持绿灯多选、批次确认、逐项历史、原路径复核、磁盘空间变化和真实重扫；黄灯有独立确认文案及强制勾选门槛。 |
| 本机真实报告对账 | 本地通过 | 只读扫描完成 18/19 个根并报告 129 项；scan→analysis 与 analysis→Dry Run 的 SHA-256 均匹配。2 个候选因所有者进程活动而拒绝；验证产物已从 `/private/tmp` 精确清理。 |
| 实现独立性 | 通过（代码层） | 运行时代码、规则、契约、测试和报告不依赖 Mole 或原参考仓库主体；详见 `docs/INDEPENDENCE_AUDIT.md`。 |
| 第三方声明 | 通过 | `THIRD_PARTY_NOTICES.md` 和 `docs/PROVENANCE.md` 保留来源及既有 MIT 义务。 |
| 正式非商业/商业许可 | 通过 | 1.0.0 起采用官方 PolyForm Noncommercial 1.0.0；`NOTICE` 记录版权所有者和商业入口，`COMMERCIAL_LICENSE.md` 明确商业使用需单独书面许可，第三方 MIT 权利继续保留。 |

## 本地复验命令

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/validate_package.py
python3 scripts/benchmark_scan.py
python3 -m compileall -q open-cleaner/scripts tests scripts
python3 tests/macos_smoke.py
git diff --check
```

Windows 实验 smoke 当前不属于发行验证命令；恢复公开入口前必须另行完成原生 runner 与真实桌面测试。

## 商业化前事项

正式对外签署商业合同时，由适用司法辖区的专业律师审阅具体合同条款。该事项不影响 1.0.0 非商业版本的技术验收。
