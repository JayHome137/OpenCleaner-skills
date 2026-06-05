# Storage Analyzer Skill

`storage-analyzer` 是一个 Codex Skill，用于只读扫描 macOS / Windows 的磁盘占用，辅助 agent 找出空间大户，并按清理风险生成交互式 HTML 报告。

它的核心目标是：先看清楚容量分布，再把候选项分成「可自动清理」「需人工判断」「谨慎清理」三类，让清理动作更可控、更可回退。

## 仓库结构

```text
.
├── LICENSE
├── README.md
├── scripts/
│   └── validate_package.py
└── storage-analyzer/
    ├── SKILL.md
    ├── agents/openai.yaml
    ├── assets/report_template.html
    ├── references/
    │   ├── macos.md
    │   └── windows.md
    └── scripts/
        ├── build_report.py
        ├── scan.py
        └── server.py
```

真正可安装的 Skill 是 `storage-analyzer/` 这个子目录。仓库根目录里的 `README.md`、`LICENSE` 和 `scripts/validate_package.py` 是为了 GitHub 发布和打包验证准备的。

## 安装

把 Skill 子目录复制到 Codex 的 skills 目录：

```bash
mkdir -p ~/.codex/skills
cp -R storage-analyzer ~/.codex/skills/storage-analyzer
```

如果你是从 GitHub 克隆本仓库，只需要复制 `storage-analyzer/` 子目录，不需要复制仓库根目录的打包文件。

## 使用方式

在 Codex 里这样调用：

```text
使用 $storage-analyzer 帮我扫描电脑存储空间，并生成分级清理报告。
```

Skill 的流程是 agent 驱动的：

1. 运行只读扫描脚本，生成 `/tmp/storage_scan.json`。
2. 由 agent 分析扫描结果，写出 `/tmp/storage_analysis.json`。
3. 使用 `scripts/server.py` 启动交互式报告，或用 `scripts/build_report.py` 生成静态 HTML 报告。

## 安全模型

扫描阶段全程只读，只使用目录遍历、容量统计和系统元信息读取。

交互式报告服务只会对分析 JSON 中明确列入白名单的路径暴露本地操作。绿灯项可以显示移到废纸篓和直接删除按钮；橙灯项只有在明确给出安全子路径时才显示可逆的移到废纸篓按钮；红灯项不暴露破坏性操作。

删除类动作仍需要用户在浏览器里确认。Skill 的设计重点是给出判断依据和安全边界，而不是静默代删文件。

## 运行要求

- 仅依赖 Python 3 标准库，不需要安装第三方包。
- macOS 是主要实测平台。
- Windows 扫描和回收站逻辑已经包含在代码中，但首次在真实 Windows 环境使用前建议单独验证路径识别和回收站行为。

## 发布前验证

运行：

```bash
python3 scripts/validate_package.py
```

验证内容包括：必需文件是否齐全、Python 脚本语法、`SKILL.md` frontmatter、`agents/openai.yaml` 元数据，以及静态报告生成链路。

## 许可证

本项目使用 MIT License，详见 [LICENSE](LICENSE)。
