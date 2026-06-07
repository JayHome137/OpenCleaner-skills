# Storage Analyzer Skill

`storage-analyzer` 是一个面向 AI Agent 的只读存储分析 Skill，用于扫描 macOS / Windows 的磁盘占用，辅助 agent 找出空间大户，并按清理风险生成交互式 HTML 报告。

它的核心目标是：先看清楚容量分布，再把候选项分成「可自动清理」「需人工判断」「谨慎清理」三类，让清理动作更可控、更可回退。

> 本仓库不是一个双击即用的独立清理软件，而是一套给 AI Agent 使用的工作流、脚本和报告模板。Agent 负责读取扫描结果、判断风险等级、生成分析 JSON；脚本负责只读扫描和报告渲染。

## 适用范围

这个项目最初按 Codex Skill 的目录结构打包，所以在 Codex 里可以直接作为 Skill 使用。但它并不只适用于 Codex。

只要一个工具能读取本仓库里的 `storage-analyzer/SKILL.md`，并能在本机运行 Python 脚本，就可以使用这套流程。典型可用场景包括：

- Codex：推荐方式，直接安装为 `~/.codex/skills/storage-analyzer`。
- Claude Code：可以把 `storage-analyzer/SKILL.md` 当作项目指令或自定义 skill 使用，再由 Claude Code 调用其中的脚本。
- OpenClaw：可以读取 `SKILL.md` 的流程说明，并在本机 shell 中运行 `scripts/scan.py`、`scripts/server.py`。
- Hermes 或其他本地 Agent：只要支持读取 Markdown 指令、执行本地命令、读写 JSON 文件，就可以复用。
- 普通终端用户：可以手动运行扫描和报告脚本，但需要自己完成 `/tmp/storage_analysis.json` 的分析内容编写。

换句话说，`storage-analyzer/` 是 Codex Skill 格式；`storage-analyzer/scripts/` 和 `storage-analyzer/assets/` 是通用 Python + HTML 资源。其他 Agent 不一定识别 Codex 的 skill 元数据，但仍然可以照着 `SKILL.md` 的流程使用。

## 平台支持

| 平台 | 状态 | 说明 |
| --- | --- | --- |
| macOS | 完整实现并实测 | 支持只读扫描、容量分组、报告生成、交互式本地服务、访达打开、移到废纸篓和白名单内直接删除。 |
| Windows | 代码已包含，需实机复核 | `scan.py` 已实现 Windows 扫描逻辑，`server.py` 已实现 Windows 回收站逻辑；首次在真实 Windows 使用前，建议验证 Python 命令、盘符扫描、路径权限和回收站行为。 |
| Linux | 暂未作为目标平台 | 当前 `SKILL.md` 和参考资料主要覆盖 macOS / Windows；Linux 可以参考脚本结构扩展，但不是现成支持目标。 |

本机是 Mac 时，优先使用 macOS 流程。Windows 也可以使用，但需要先安装 Python 3，并把命令里的 `python3` 改成 `python` 或 `py -3`。

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

## Codex 安装

把 Skill 子目录复制到 Codex 的 skills 目录：

```bash
mkdir -p ~/.codex/skills
cp -R storage-analyzer ~/.codex/skills/storage-analyzer
```

如果你是从 GitHub 克隆本仓库，只需要复制 `storage-analyzer/` 子目录，不需要复制仓库根目录的打包文件。

## 其他 Agent 使用方式

其他 Agent 不需要使用 Codex 的安装目录。推荐做法是让 Agent 读取：

```text
storage-analyzer/SKILL.md
```

然后按里面的流程执行：

```bash
python3 storage-analyzer/scripts/scan.py > /tmp/storage_scan.json
```

Agent 分析 `/tmp/storage_scan.json` 后，写出符合 `build_report.py` 注释 schema 的 `/tmp/storage_analysis.json`，再启动交互式报告：

```bash
python3 storage-analyzer/scripts/server.py /tmp/storage_analysis.json
```

如果只需要留存或分享一份静态报告，可以改用：

```bash
python3 storage-analyzer/scripts/build_report.py /tmp/storage_analysis.json ~/Desktop/storage-report.html
```

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
- macOS 自带 `python3`、`du`、`diskutil`、`osascript`，是目前主要实测平台。
- Windows 需要用户自行安装 Python 3，常用命令是 `python` 或 `py -3`。
- Windows 扫描和回收站逻辑已经包含在代码中，但首次在真实 Windows 环境使用前建议单独验证路径识别、权限边界和回收站行为。
- 交互式删除能力依赖本地报告服务 `server.py`；如果直接打开静态 HTML 文件，只能查看报告和复制命令，不能调用本机文件操作。

## 来源与修改说明

本项目基于 [KKKKhazix/khazix-skills](https://github.com/KKKKhazix/khazix-skills) 仓库中的同名 `storage-analyzer` 技能修改而来。原仓库由 KKKKhazix 维护，并采用 MIT License。

当前仓库在原技能基础上做了适配和整理，包括面向 Codex 的 Skill 打包结构、中文 README、平台适用说明、GitHub 发布结构、`agents/openai.yaml` 元数据，以及本仓库维护所需的验证脚本。

## 许可证

本项目使用 MIT License，详见 [LICENSE](LICENSE)。
