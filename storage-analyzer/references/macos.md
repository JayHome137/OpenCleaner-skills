# macOS 数据布局与分级参考

分析 macOS 扫描结果时读这份。讲"东西存在哪、怎么辨认、归哪一级"。

## 关键目录

| 目录 | 装什么 | 典型分级 |
|---|---|---|
| `~/Library/Caches/*` | 应用/工具缓存（浏览器、Homebrew、pip、playwright） | 🟢 可自动清 |
| `~/.cache/*`、`~/.npm`、`~/.cargo`、`~/.gradle`、`~/.m2` | 开发缓存 | 🟢 |
| `~/Library/Developer/Xcode/DerivedData` | Xcode 构建缓存 | 🟢 |
| `/Library/Developer/CoreSimulator/Volumes/*`、`/Library/Developer/CoreSimulator/Caches/dyld` | Xcode 平台 runtime / APFS 挂载卷 / dyld 缓存 | 🟡 |
| `/Library/Developer/CommandLineTools`、`/Applications/Xcode.app` | Apple 开发工具本体 | 🔴（不用时走正规卸载） |
| `~/Library/Containers/<UUID 或 bundleid>` | 沙盒应用数据（聊天记录、离线视频、设置） | 🟡 多为用户数据 |
| `~/Library/Application Support/*` | 应用数据（Chrome Profile、Claude VM、飞书） | 🟡 |
| `~/Downloads` 里的 .dmg/.pkg | 安装包残留 | 🟢 |
| `~/Library/Application Support/*/Cache`、`GPUCache` | Electron/浏览器应用缓存 | 🟢（只清缓存子目录） |
| `~/Library/Application Support/*/vm_bundles`、`*.img`、`*.zst` | 应用 VM/运行时镜像 | 🟡 |
| `~/Library/Application Support/*/spool/*.tar.gz` | 备份暂存包 | 🟡（先确认外部副本） |
| `~/Library/PPS`、`~/Library/Application Support/QvodPlayer` | 用户目录旧软件残留 | 🟡 |
| `/Library/Internet Plug-Ins/*`、`/Library/Frameworks/Adobe AIR.framework`、`/Library/Application Support/Alipay` | 系统级旧插件/残留 | 🟡（需管理员确认） |
| `/private/var/db/diagnostics`、`/private/var/db/uuidtext`、`/private/var/folders/*` | 系统诊断日志/临时缓存 | 多数归蓝色说明，谨慎 |
| `/Applications/*.app` | 应用本体 | 🔴 仅当重复/想卸时上灯，否则归蓝色 |
| 系统文件、APFS 本地快照 | 系统 | 不上灯，归蓝色"系统及其他" |

## 必做的系统数据补扫

macOS「系统数据」经常不是系统垃圾，而是 HOME 之外的可解释目录。分析时必须核对这些只读命令的等价信息（`scan.py` 已输出对应分组）：

- `/Library/Developer/CoreSimulator`：用来解释 Xcode/iOS/watchOS/tvOS/xrOS runtime、APFS 挂载卷和 dyld 缓存。
- `/Library/Developer`、`/Library`：用来解释 CommandLineTools、系统级插件、字体、打印机、旧软件残留。
- `/private/var`：用来解释诊断日志、uuidtext、`var/folders` 临时缓存；通常只说明，不建议直接删。

对 CoreSimulator 要交叉核对：

```bash
xcrun simctl runtime list
du -sh /Library/Developer/CoreSimulator/Volumes/* /Library/Developer/CoreSimulator/Caches/* 2>/dev/null
diskutil apfs list | rg -i 'Simulator|CoreSimulator|Capacity Consumed|Mount Point'
```

`xcrun` 显示的是 Xcode 识别的 runtime；`du` 和 `diskutil` 更接近实际 APFS 占用。报告里要把这三者的口径说清楚。

## 辨认"神秘 UUID 容器"

`~/Library/Containers/` 下 UUID 命名的大目录，要查清属于哪个 App：
- `ls` 进 `Data/Documents/`、`Data/Library/`，找带 bundle id 的子目录（如 `com.bilibili.bbad` → 哔哩哔哩）
- 大头常藏在隐藏目录（如 `.Downloads/` 里的 `.bilitask` 离线视频）
- 仍只读，别动文件

## 间接释放（写进 long_term，不上红灯）

- 系统"可清除空间"磁盘紧张时自动回收
- 重启释放部分 swap / 临时快照
- `brew cleanup --prune=all`、清 Xcode DerivedData
- Xcode runtime 用 Xcode Settings > Platforms 删除；不要直接 `rm /Library/Developer/CoreSimulator/Volumes`
- NAS 适合放 Xcode 归档/备份，不适合承载 CoreSimulator runtime 或 dyld 缓存
- 调整 Time Machine 本地快照保留策略

## 删除机制

`server.py` 在 macOS 用 osascript 调访达入废纸篓；首次弹自动化授权，点允许。
