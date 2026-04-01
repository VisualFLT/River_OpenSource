PMEM 设备通讯控制报告
======================

目标
----
- 说明精简后的 RiverServerSingleDll 仅保留 pmem 设备时，与 winpmem 驱动的通讯流程、通道和关键控制点。

构建与入口
----------
- 设备筛选：`LcCreate_FetchDevice` 仅接受 `pmem`，其他设备名直接拒绝。
- 打开流程：`LcCreate` → `DevicePMEM_Open`（失败重试一次）→ 初始化上下文、加载/连接驱动、获取物理内存映射、设置回调。

驱动加载与句柄
--------------
- 驱动文件：默认尝试与 DLL 同目录的 `winpmem_x64.sys`/`winpmem_x86.sys`；支持 `pmem://<path>` 覆盖。
- 服务控制（SCM）：
  - 查询已运行：`OpenSCManager` → `OpenServiceA("pmem")`。
  - 加载驱动：`CreateServiceA` → `StartServiceA`（若不存在则创建）。
- 设备句柄：`CreateFileA("\\\\.\\pmem", GENERIC_READ|WRITE, FILE_SHARE_READ|WRITE, OPEN_EXISTING)`，用于后续全部 IO。
- 清理：引用计数归零且本进程加载过驱动时，`DevicePMEM_SvcClose` 停止并删除服务。

数据面通讯
----------
- 回调：`ctxLC->pfnReadScatter = DevicePMEM_ReadScatter`。
- 读路径（每个 MEM_SCATTER）：
  - `SetFilePointerEx(hFile, offset, FILE_BEGIN)`
  - `ReadFile(hFile, buf, len, &cbRead, NULL)`
- 写支持：无（未设置写回调），视为只读采集。

控制面通讯（IOCTL）
-------------------
- 获取内存信息：`DeviceIoControl(PMEM_INFO_IOCTRL, ...)` → 返回 `PmemMemoryInfo`（CR3、KernBase、PsLoadedModuleList、物理段 Run[i] 等）。
  - 解析并调用 `LcMemMap_AddRange` 建立内部物理内存映射。
- 设置采集模式：`DeviceIoControl(PMEM_CTRL_IOCTRL, dwMode = PMEM_MODE_PTE)`，强制 PTE 模式以兼容 VSM。
-（无写启用 IOCTL；未使用 PMEM_WRITE_ENABLE）

选项查询接口
------------
- `ctxLC->pfnGetOption = DevicePMEM_GetOption` 支持：
  - `LC_OPT_MEMORYINFO_VALID`：1（可用）
  - OS/内核信息：版本高低位、CR3、PfnDataBase、PsLoadedModuleList、PsActiveProcessHead、KernBase
  - 仅 64 位：返回机器类型 0x8664，32/PAE 标志返回 0

日志与诊断
----------
- 文件：`C:\pmem_log\pmem.log`（自动创建目录），记录驱动加载/IOCTL/读失败等，含时间戳。
- 详细输出：`LC_PRINTF_VVV` 级别可打印每次 READ 的偏移与数据十六进制转储。

调用链摘要
----------
- `LcCreate` → `DevicePMEM_Open`（双次尝试） → `DevicePMEM_SvcStatusRunning/DevicePMEM_SvcStart`（SCM + CreateFile） → `DevicePMEM_GetMemoryInformation`（PMEM_INFO_IOCTRL + 映射 + PMEM_CTRL_IOCTRL） → 注册回调（读/选项/关闭） → 上层 `LcRead/LcReadScatter` 通过回调落到 `ReadFile` 读取物理内存。

使用/验证建议
-------------
- 若驱动加载失败：确认管理员权限与驱动路径（必要时用 `pmem://` 指定）。
- 采集异常：启用详细日志并检查 `C:\pmem_log\pmem.log`，关注 IOCTL 失败或 READ 失败的 gle。


