# 独立实现审计

## 结论

当前运行主体、规则、契约、测试和报告交互没有对 Mole 或原参考仓库的源码依赖。与初始提交逐行比较后，旧文件中仍保持完全相同的内容只包括通用语言结构、文件格式标记、标准入口写法，以及用户明确要求保留的产品名称和报告标题；没有发现保留的上游函数体、规则文本、算法注释或旧路径提交协议。

这项结论不撤销仓库历史中已经产生的 MIT 许可和署名记录。`THIRD_PARTY_NOTICES.md` 继续保留上游 notice。

## 审计基线

- 初始引入提交：`de82aa35461d533c61aa7099c774a612199c0311`。
- 审计范围：Skill 指令、扫描器、报告生成器、服务端、HTML 模板和两份平台参考。
- Mole 检查范围：`opencleaner-skills/`、`scripts/`、`tests/`、`.github/`。
- 方法：Git 行级差异、旧/新完全相同行交集、运行目录标识搜索、当前模块依赖检查。

## 行级结果

| 文件 | 初始行数 | 当前行数 | Git 删除旧行 | 相同行性质 |
| --- | ---: | ---: | ---: | --- |
| `opencleaner-skills/SKILL.md` | 117 | 138 | 71 | frontmatter 标记、代码围栏、项目名称和通用标题。 |
| `opencleaner-skills/scripts/scan.py` | 320 | 428 | 287 | Python imports、`try`/`continue`、标准 main 入口和通用单位列表。 |
| `opencleaner-skills/scripts/build_report.py` | 55 | 65 | 40 | shebang、Usage 入口、标准 main 入口和 `os`/`sys` imports。 |
| `opencleaner-skills/scripts/server.py` | 250 | 273 | 221 | 标准库 imports、Usage 入口、KeyboardInterrupt 和 main 入口。 |
| `opencleaner-skills/assets/report_template.html` | 497 | 521 | 439 | HTML 标签、脚本/样式闭合标签、报告标题。 |
| `opencleaner-skills/references/macos.md` | 62 | 40 | 50 | 无完全相同的非空行。 |
| `opencleaner-skills/references/windows.md` | 33 | 37 | 24 | 仅“多盘符”通用标题。 |

相同的通用语法行不构成项目主体实现。重要行为已经迁移到本项目独立的数据契约、规则目录、策略内核和 action-ID 协议。

## 标识与依赖检查

- Mole、`tw93/mole`、GPL 标识未出现在运行时代码、测试或工作流中。
- `KKKKhazix/khazix-skills` 和原作者标识未出现在运行时代码、测试或工作流中。
- 上述来源只保留在仓库级来源和许可说明中。
- 报告模板不存在旧版 `data-paths`、`authorizedPaths` 或 `postAction(paths, mode)` 协议。
- Python 运行时只导入标准库和本 Skill 内部模块。

## 边界

行级差异可以证明当前文件没有保留大段原文，但不能替代法律层面的著作权判断。正式切换到非商业/商业双重许可前，仍应保留第三方 notice，并对最终许可文本进行适用司法辖区的专业审阅。
