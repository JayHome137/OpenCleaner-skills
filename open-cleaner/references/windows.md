# Windows 实验实现（当前关闭）

> 当前发行版只支持 macOS。本文件与相关规则、实现和 smoke 脚本仅为后续独立测试保留；公开扫描、分类、操作计划和文件操作入口必须拒绝 Windows。

## 可由规则授权的范围

| 规则 | 允许目标 | 限制 |
| --- | --- | --- |
| `windows.temp-entry` | `%TEMP%` 下的具体子项 | 不允许整体操作 Temp 根目录。 |
| `windows.pip-cache` | `%LOCALAPPDATA%\pip\Cache` | 仅包下载缓存。 |
| `windows.go-build-cache` | `%LOCALAPPDATA%\go-build` | 仅 Go 编译缓存。 |
| `common.user-cache-entry` | `%USERPROFILE%\.cache` 下的具体子项 | 未知模型或应用状态可提高为黄灯。 |
| `common.npm-content-cache` | `%USERPROFILE%\.npm\_cacache` | 不包含 npm 用户配置。 |
| `common.gradle-cache-entry` | `%USERPROFILE%\.gradle\caches` 下的具体子项 | 不包含项目、wrapper 和用户配置。 |

规则目标仍必须位于真实用户主目录内，并通过路径、符号链接、文件身份、父目录、所有者工具运行状态和短期计划复核。已知所有者进程活动或状态未知时失败关闭；所有者工具命令只展示，不自动执行。

## 必须人工判断的范围

- `%APPDATA%`：漫游配置、数据库和用户状态，默认黄灯。
- `%LOCALAPPDATA%` 中未命中规则的应用目录：可能同时包含缓存和核心数据。
- `Downloads` 和其他盘符：可能是用户唯一副本，不按扩展名或文件年龄自动授权。
- 浏览器 Profile：只有明确缓存子目录才可能进入规则，书签、登录态和扩展数据保持黄灯。
- `.nuget\packages`、`.m2`、模型目录和大型工具链：重下载成本或状态不明确，默认黄灯。

黄灯默认只能打开查看。受控报告仅可为 `Downloads` 或 `%TEMP%` 的当前用户直接子项生成 `reviewed_trash` 候选；目标不能是根本身、深层后代、隐藏/敏感目录或符号链接。用户逐项确认后，服务端还要签发与当前计划和完整 action ID 集绑定的 120 秒一次性令牌。普通绿灯 `trash` 与黄灯 `reviewed_trash` 不得混批。

## 应用和系统内容

- `Program Files` 和 `Program Files (x86)` 只用于识别应用体积，不由报告服务删除。
- `Windows`、`WinSxS`、更新缓存、`pagefile.sys` 和 `hiberfil.sys` 不进入文件操作计划。
- 系统内容通过 Windows 设置、存储感知、磁盘清理或应用卸载入口处理。
- 需要管理员权限的目标只提供说明。

## 多盘符

报告展示所有检测到的盘符，但规则只授权当前用户主目录中的确定性目标。D:、E: 等用户数据盘默认黄灯，除非未来增加具有恢复证据和独立测试的明确规则。

## Recycle Bin 行为

Windows 使用 `SHFileOperationW` 和 `FOF_ALLOWUNDO` 移入回收站，同时检查错误码和用户中止状态。失败时停止，不回退到永久删除。API 返回成功后仍要确认原路径已经不存在，并记录操作前后的磁盘可用空间；移入回收站本身通常不会释放内容占用。
