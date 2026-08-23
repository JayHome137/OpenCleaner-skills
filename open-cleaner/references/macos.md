# macOS 分析边界

## 可由规则授权的范围

当前规则只覆盖明确可恢复的缓存目标：

| 规则 | 允许目标 | 限制 |
| --- | --- | --- |
| `macos.library-cache-entry` | `~/Library/Caches` 下的具体子项 | 不允许操作 `Caches` 根目录；运行中的应用缓存仍应先关闭应用。 |
| `macos.xcode-derived-data-entry` | `~/Library/Developer/Xcode/DerivedData` 下的具体项目 | 不允许操作 DerivedData 根目录。 |
| `macos.pnpm-cache-entry` | `~/Library/pnpm/store` 下的具体缓存项 | 不操作 pnpm 配置或项目目录。 |
| `common.user-cache-entry` | `~/.cache` 下的具体子项 | 未知模型、会话或下载内容可由 Agent 提高为黄灯。 |
| `common.npm-content-cache` | `~/.npm/_cacache` | 不包含 `~/.npmrc` 或其他配置。 |
| `common.gradle-cache-entry` | `~/.gradle/caches` 下的具体子项 | 不包含项目源码、wrapper 或用户配置。 |

规则授权仅说明路径类别可恢复，执行时仍要通过保护目录、符号链接、文件身份、父目录、所有者工具运行状态和短期计划检查。pnpm、npm、Gradle、Chrome、Codex、Claude、UTM、Tart、Docker/OrbStack 和微信等已知识别项在进程活动或状态未知时失败关闭；展示的所有者工具命令不会自动执行。

## 必须人工判断的范围

- `~/Library/Containers`、`Group Containers`：可能含聊天记录、离线媒体和应用文档。
- `~/Library/Application Support`：可能含浏览器 Profile、数据库、虚拟机镜像和登录状态。
- `~/Downloads`：安装包也可能是用户唯一保留副本，不按扩展名自动授权。
- `/Library/Developer/CoreSimulator`：使用 Xcode Settings > Platforms 或 `xcrun simctl runtime list` 判断，不直接操作挂载卷。
- `/Library`、`/private/var`：只解释系统数据，不由本 Skill 执行。
- 备份压缩包、磁盘镜像、模型和项目依赖：没有完整恢复证据时保持黄灯。

黄灯默认只能打开查看。受控报告仅可为 `~/Downloads`、`/private/tmp` 或当前用户临时根的直接子项生成 `reviewed_trash` 候选；目标必须属于当前用户，不能是根本身、深层后代、隐藏/敏感目录或符号链接。用户逐项确认后，服务端还要签发与当前计划和完整 action ID 集绑定的 120 秒一次性令牌。普通绿灯 `trash` 与黄灯 `reviewed_trash` 不得混批。

项目阶段例外只扩展到确定性 allowlist 生成目录，例如 `.build`、`DerivedData`、测试报告和测试缓存。执行本轮开发的 Agent 必须先确认测试/构建验证成功、源码已有恢复检查点、相关进程退出；扫描器再检查项目清单、Git ignored 且不含 tracked 内容、Archives/发布包排除、30 分钟静置期和打开文件。任一条件缺失都保持黄灯但不生成操作按钮。通过后也只能 `reviewed_trash`，不能自动或永久删除；首次续用可能需要重新构建或重新下载依赖。

## 应用和系统内容

- `/Applications/*.app` 只允许在访达定位，由用户使用正规卸载方式处理。
- `/System`、`/Library`、`/private`、`/Volumes` 和磁盘根不能进入 Trash 计划。
- APFS 快照、swap、系统日志数据库和系统更新内容不作为文件级清理目标。
- 需要管理员权限的目标只提供说明，不在本地报告服务中执行。

## 陌生目录分析

可以只读查看目录结构、Bundle ID、文件类型和少量元数据来确认所属应用。不要因为 UUID 名称、`Cache` 字样、年龄或体积就降低风险等级。无法证明可恢复时保持黄灯，并优先给出应用内清理或文件管理器查看路径。

## Trash 行为

macOS 优先使用系统 `/usr/bin/trash`；系统没有该命令时使用 Finder AppleScript。两种方式都失败时操作停止，不移动到自建目录，也不永久删除。系统调用返回成功后仍要确认原路径已经不存在，并记录操作前后的磁盘可用空间；移入废纸篓本身通常不会释放内容占用。
