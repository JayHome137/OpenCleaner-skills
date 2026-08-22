# 1.0.0 验收矩阵

> 验证日期：2026-08-22
> 边界：只操作仓库内测试数据和系统临时目录，不操作用户真实文件；远程 runner 状态以 GitHub Actions 为准。

## 结论

代码、macOS/Windows 端到端链路、报告界面、实现独立性和正式许可均已通过验收。实现提交 `ddfc6c4e695579b431a022a43343fdb8427ad6f5` 已在 GitHub Actions 的真实 macOS 与 Windows runner 上完成验证。

## 验收结果

| 验收项 | 状态 | 证据与边界 |
| --- | --- | --- |
| Skill 形态 | 通过 | 保留 `opencleaner-skills/SKILL.md`、Agent 元数据和标准包结构；未改造成终端套件。 |
| 包结构与契约 | 通过 | `python3 scripts/validate_package.py`；scan、analysis、action-plan schema 均受验证。 |
| 单元与安全回归 | 通过 | 53 个测试通过，覆盖规则、符号链接、路径穿越、保护目录、目标或父目录变化、并发重放、Trash 失败、请求边界和移动端网格收缩不变量。 |
| Dry Run 边界 | 通过 | Dry Run 具有显式 purpose，服务端和文件操作内核均拒绝执行。 |
| 文件操作边界 | 通过 | 仅允许 `open`、`trash`；没有永久删除回退；副作用前要求日志可写并完整复核整批目标。POSIX 操作日志目录/文件权限为 `0700`/`0600`，并拒绝符号链接日志。 |
| macOS 端到端 | 通过 | 本地 `python3 tests/macos_smoke.py` 和 [macOS run 32548944726](https://github.com/JayHome137/OpenCleaner-skills/actions/runs/32548944726) 均输出 `MACOS_SMOKE_OK`；只处理临时 HOME fixture。 |
| Windows 路径逻辑 | 通过 | 单元测试覆盖 Windows 规则与大小写不敏感路径；工作流和原生 smoke 脚本已配置。 |
| Windows 原生端到端 | 通过 | [Windows run 32548944701](https://github.com/JayHome137/OpenCleaner-skills/actions/runs/32548944701) 在 `windows-latest` 完成包校验、53 个单元测试和 Recycle Bin smoke，并输出 `WINDOWS_SMOKE_OK`。 |
| 扫描确定性 | 通过 | 1 worker 与 4 workers 输出相同 SHA-256：`9d1aa96d6e0173d82ae281fe412aa19bde0b2cc4f8948e5439341c9c8bd01e6d`。 |
| 报告内容与布局 | 通过 | 保留磁盘总览、Top 5、执行建议、绿黄红卡片、长期建议及颜色语义；桌面和 390x844 移动视口无页面溢出。 |
| 报告动作协议 | 通过 | 交互报告显示 3 个受控按钮；按钮只有 `data-action-ids`，没有 `data-paths`；操作历史初始隐藏且为空。 |
| 操作结果呈现 | 通过 | 报告支持显示状态、规则、路径、原路径复核和磁盘空间实测变化。 |
| 实现独立性 | 通过（代码层） | 运行时代码、规则、契约、测试和报告不依赖 Mole 或原参考仓库主体；详见 `docs/INDEPENDENCE_AUDIT.md`。 |
| 第三方声明 | 通过 | `THIRD_PARTY_NOTICES.md` 和 `docs/PROVENANCE.md` 保留来源及既有 MIT 义务。 |
| 正式非商业/商业许可 | 通过 | 1.0.0 起采用官方 PolyForm Noncommercial 1.0.0；`NOTICE` 记录版权所有者和商业入口，`COMMERCIAL_LICENSE.md` 明确商业使用需单独书面许可，第三方 MIT 权利继续保留。 |

## 本地复验命令

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/validate_package.py
python3 scripts/benchmark_scan.py
python3 -m compileall -q opencleaner-skills/scripts tests scripts
python3 tests/macos_smoke.py
git diff --check
```

Windows runner 使用：

```powershell
python scripts/validate_package.py
python tests/windows_smoke.py
```

## 商业化前事项

正式对外签署商业合同时，由适用司法辖区的专业律师审阅具体合同条款。该事项不影响 1.0.0 非商业版本的技术验收。
