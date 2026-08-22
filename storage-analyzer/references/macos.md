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

规则授权仅说明路径类别可恢复，执行时仍要通过保护目录、符号链接、文件身份和短期计划检查。

## 必须人工判断的范围

- `~/Library/Containers`、`Group Containers`：可能含聊天记录、离线媒体和应用文档。
- `~/Library/Application Support`：可能含浏览器 Profile、数据库、虚拟机镜像和登录状态。
- `~/Downloads`：安装包也可能是用户唯一保留副本，不按扩展名自动授权。
- `/Library/Developer/CoreSimulator`：使用 Xcode Settings > Platforms 或 `xcrun simctl runtime list` 判断，不直接操作挂载卷。
- `/Library`、`/private/var`：只解释系统数据，不由本 Skill 执行。
- 备份压缩包、磁盘镜像、模型和项目依赖：没有完整恢复证据时保持黄灯。

## 应用和系统内容

- `/Applications/*.app` 只允许在访达定位，由用户使用正规卸载方式处理。
- `/System`、`/Library`、`/private`、`/Volumes` 和磁盘根不能进入 Trash 计划。
- APFS 快照、swap、系统日志数据库和系统更新内容不作为文件级清理目标。
- 需要管理员权限的目标只提供说明，不在本地报告服务中执行。

## 陌生目录分析

可以只读查看目录结构、Bundle ID、文件类型和少量元数据来确认所属应用。不要因为 UUID 名称、`Cache` 字样、年龄或体积就降低风险等级。无法证明可恢复时保持黄灯，并优先给出应用内清理或文件管理器查看路径。

## Trash 行为

macOS 优先使用系统 `/usr/bin/trash`；系统没有该命令时使用 Finder AppleScript。两种方式都失败时操作停止，不移动到自建目录，也不永久删除。系统调用返回成功后仍要确认原路径已经不存在，并记录操作前后的磁盘可用空间；移入废纸篓本身通常不会释放内容占用。
