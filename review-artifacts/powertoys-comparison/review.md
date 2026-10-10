# Locksmith 与 PowerToys File Locksmith 的来源对照

核对日期：2026-10-10。本报告保留实施前的审查快照，仅审查与扫描、路径匹配、进程结束相关的实现及历史；当时未修改两边的生产代码。

后续已按讨论决定修复 Rust 实现，进度与验证见[修复记录](../remediation.md)。本报告中的 Rust 行号对应旧版本，不能用来定位修复后的实现。PowerToys 生产代码未修改。

## 结论

问题来源是混合的，不能全部归因于上游，也不能全部归因于移植：

- 模块路径重新打开、按 PID 重新获取要结束的进程，在上游早期版本和当前版本中都存在。
- UTF-8 切片 panic、一次模块失败丢掉整组结果，以及当前长路径重试的具体错误，是 Rust 侧的实现或后续修改引入的。
- 进程遍历两边都有首尾处理差异，但上游跳过第一条，Rust 跳过最后一条，不能称为同一缺陷。
- 上游已经缓存同一 PID 的进程句柄，并对系统信息缓冲区使用倍增和容量上限；Rust 没有保留这些设计。
- 没找到“这八项问题在当前上游已整体修复”的证据。核心文件最近的历史修改主要是 2024 年类型转换重构。

## 审查版本与来源边界

- PowerToys 本地 HEAD：`7b6789c576b304c7e1eda8ce571cc1b0afd280ab`，提交日期 2026-10-09。
- Rust HEAD：`d3a0536480457850518bd80df04c273be2bc34ad`。
- 已确认所检查的 PowerToys 核心、UI 结束进程及 CLI 文件与 HEAD 没有差异。未拉取或修改上游；不宣称已验证本地 HEAD 与此刻远端完全相同。
- 两个仓库都有可用的完整本地历史。Rust 最早提交在 2023-12，扫描实现陆续在该月形成；2025 年还有重要后续修改。
- 当时移植所用的精确 PowerToys 提交仍未知。以下“上游已有”表示历史源码存在该模式，不证明某行 Rust 必然直接复制自某个提交。

## 八项缺陷逐项对照

| 原审查项 | 当前 PowerToys 实现 | 来源判断 |
|---|---|---|
| 1. UTF-8 前缀切片 panic | 使用 `std::wstring_view` 和 `substr`，没有 Rust UTF-8 字符边界检查导致的同类 panic | Rust 侧引入；出问题的函数在 `3088e15`（2025-05-27）新增，并非最初移植即有 |
| 2. PID 复用导致误结束进程 | UI 的 `EndTask` 重新 `GetProcessById`，当前 CLI 重新 `OpenProcess(PROCESS_TERMINATE, pid)`；结果模型未保存创建时间或原始进程句柄 | 上游也存在相同身份竞态。UI 从早期版本即如此；Rust 的结束功能在 `7f91019`（2025-05-19）增加，不能认定其必然直接沿用了上游 UI |
| 3. 重新打开其他进程的模块路径 | `process.modules` → `path_to_kernel_name` → `CreateFileW`，在匹配目标前打开路径 | 很明确的上游已有设计；2022 年初版就存在，当前仍在。潜在网络认证影响仍有账号、共享可达性及认证策略等条件，未做认证泄露实验 |
| 4. 长路径只增加一点容量、忽略重试长度 | 上游改用一个很大的缓冲区，但错误地从 `GetModuleFileNameExW(process, ...)` 切换到 `GetModuleFileNameW(mod, ...)` | 双方有长路径问题，但根因不同。Rust 的容量/长度错误是本地逻辑；上游的错误是改查了当前进程 |
| 5. 跳过最后一条进程记录 | 上游循环先移动到下一条再处理，跳过第一条，但会处理最后一条 | Rust 的“漏最后一条”是移植中改变遍历顺序后的具体错误；不是照搬上游同一 bug。上游首条常为 Idle，实际影响不能与漏普通进程简单等同 |
| 6. 单个模块失败丢弃全部模块 | 每个模块的文件路径转换在外层逐个执行；某路径转换失败返回空字符串，其他模块仍会继续 | Rust 中 `?` 使整组模块失败、外层再置为空，是本地扩大了错误影响。上游仍缺少完整的部分失败诊断，并有模块名失败处理问题 |
| 7. 失败退出码为 0 | 当前 CLI 能对部分参数错误和等待超时返回 1，但结束进程失败不改变最终 0；无效目标被过滤成没有结果，扫描错误也能变成空结果 | 两边有类似的“失败与无结果混淆”。当前 PowerToys CLI 在 2026-01 才加入，晚于 Rust CLI，不能作为当时移植的来源 |
| 8. 只忽略 ASCII 大小写 | 上游直接精确比较 `wstring` 的内核路径，未实现 ASCII 或 Unicode 忽略大小写比较 | Rust 的 ASCII 比较是后来本地添加的功能，而且不完整。上游不是更完善的 Windows 大小写比较实现；内核查询可能统一部分路径拼写，不能仅凭字符串测试断言实际漏报 |

相关位置：

- Rust 路径比较：[path_ext.rs:57](C:/Users/fu/.codex/worktrees/5fc9/locksmith/src/path_ext.rs:57)。
- Rust 遍历与模块错误传播：[process_ext.rs:46](C:/Users/fu/.codex/worktrees/5fc9/locksmith/src/process_ext.rs:46)、[process_ext.rs:111](C:/Users/fu/.codex/worktrees/5fc9/locksmith/src/process_ext.rs:111)。
- PowerToys 前缀比较与模块路径打开：[FileLocksmith.cpp:13](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/FileLocksmith.cpp:13)、[FileLocksmith.cpp:86](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/FileLocksmith.cpp:86)。
- PowerToys 长路径与进程遍历：[NtdllExtensions.cpp:27](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/NtdllExtensions.cpp:27)、[NtdllExtensions.cpp:355](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/NtdllExtensions.cpp:355)。
- PowerToys UI 结束进程：[MainViewModel.cs:153](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithUI/ViewModels/MainViewModel.cs:153)；CLI：[main.cpp:22](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithCLI/main.cpp:22)、[CLILogic.cpp:248](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithCLI/CLILogic.cpp:248)。

## 历史中的关键证据

1. PowerToys `db191b8b75`（2022-10-28 初版）已有：模块路径重新打开、按 PID 结束进程、长路径分支错误接口、先移动再处理的进程遍历，以及按 PID 缓存进程句柄。
2. `b17955c968`（2022-12-16）为处理句柄查询卡住而加入工作线程、`detach` 和 `TerminateThread`。这不是后续 Rust 移植引入的上游代码。
3. `5ab83c6ad2`（2023-11-15）的扫描核心已经与当前实现非常接近，覆盖 Rust 最初开发前的时间范围。
4. `fb5ed13386`（2024-08-08）对这些核心位置主要修改了显式类型转换，没有修复上述长路径分支、遍历和线程生命周期逻辑。当前 `NtdllExtensions.cpp` 的最后一次修改就是该提交；当前 `FileLocksmith.cpp` 也没有后来的相关修复。
5. Rust `2b642ab`（2023-12-28）出现漏最后一条的进程遍历；`f70f7c9`（2023-12-29）出现整组模块错误传播和模块路径转换。
6. Rust `b7a821d` 的作者日期为 2024-01-19，提交日期为 2025-02-17：重试扩容使用第一次长度，不能推导完整路径长度。不能将两个日期混为一谈。
7. Rust `27310a3` 的作者日期为 2025-02-14，提交日期为 2025-02-17：把 `actual_len` 改为不可变、忽略第二次返回值并只增加一个字符。`7f91019`（2025-05-19）又改回使用旧长度截取，形成今天的具体错误。
8. Rust `3088e15`（2025-05-27）新增当前目录匹配函数，同时引入任意 UTF-8 字节切片和 ASCII-only 大小写比较。
9. PowerToys CLI 在 `03aec1a9a7`（2026-01-06）才加入，因此当前 CLI 相似行为只能作为现状对照，不能证明历史继承。

## 上游还存在的独立问题

### [P1] 分离线程后获取原生句柄，超时处理不能可靠终止旧工作线程

位置：[NtdllExtensions.cpp:252](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/NtdllExtensions.cpp:252)、[NtdllExtensions.cpp:267](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/NtdllExtensions.cpp:267)。

代码先 `offload_function.detach()`，随后调用 `TerminateThread(offload_function.native_handle(), 1)`，并且不检查返回值。本机 MSVC 的 `detach()` 清空内部线程对象，之后 `native_handle()` 为 null。超时分支仍递增共享下标、关闭句柄并继续启动工作线程。

如果旧调用稍后返回，旧线程会继续访问按引用捕获的缓冲区、map 和结果 vector；可能与新线程并发访问，也可能访问已经销毁的数据。正常完成路径同样没有明确的线程完成等待。共享原子下标不能替代整个线程生命周期同步。

验证：本机 MSVC 实际线程测试确认 detach 后句柄为 null。没有执行 TerminateThread，也没有在 PowerToys 中制造挂起或复现 UAF。内存破坏是控制流推导的条件性后果。

建议：不要将强制结束线程当作安全的超时恢复机制。优先以可终止的辅助进程隔离可能挂起的查询，或使用有明确生命周期和完成同步的方案。微软也明确指出 [TerminateThread 会带来资源和共享状态问题](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread)。

### [P2] 长模块路径分支查错进程

位置：[NtdllExtensions.cpp:32](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/NtdllExtensions.cpp:32)。

第一次查询使用 `GetModuleFileNameExW(process, mod, ...)`，扩容后却调用 `GetModuleFileNameW(mod, ...)`。后者只查询当前进程中的模块；把目标进程的模块地址传入，可能失败或查到当前进程同地址的模块。代码忽略失败并返回该缓冲区结果。

验证：从当前文件直接抽取函数、替换 API 为 mock，确认扩容分支调用当前进程接口。未搭建真实长路径 DLL。接口契约：[GetModuleFileNameW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew)、[GetModuleFileNameExW](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulefilenameexw)。

建议：全程使用原目标进程接口，更新每次返回长度，显式处理失败和截断。

### [P2] 部分失败路径泄漏进程或令牌句柄

位置：[NtdllExtensions.cpp:63](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/NtdllExtensions.cpp:63)、[NtdllExtensions.cpp:306](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/NtdllExtensions.cpp:306)。

- `process_modules` 已成功 OpenProcess，但 EnumProcessModules 失败时直接返回，跳过最后的 CloseHandle。
- `pid_to_user` 在 OpenProcessToken 或后续查询失败时提前返回，跳过进程或令牌释放。
- 当前 CLI 的 `--wait` 可以重复扫描，这些失败路径会累计泄漏。

验证：抽取实际 `process_modules` 函数，mock 打开成功/枚举失败，计数确认打开一次、关闭零次。令牌分支为静态控制流确认，未用真实系统累计泄漏。

建议：采用 WIL 等已有 RAII 句柄类型，让所有提前返回和异常路径自动释放。Rust 当前自定义 RAII 至少已经解决了这些常规提前返回泄漏；不能把所有权封装建议误解成 Rust 比上游更差。

### [P2] 模块名查询失败后仍读取未初始化缓冲区

位置：[NtdllExtensions.cpp:26](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/NtdllExtensions.cpp:26)、[NtdllExtensions.cpp:38](D:/playground/dotnet/PowerToys/src/modules/FileLocksmith/FileLocksmithLibInterop/NtdllExtensions.cpp:38)。

栈上的 `wchar_t buffer[MAX_PATH + 1]` 未初始化。GetModuleFileNameExW 返回零时，代码没有处理失败，而是继续用 lstrlenW 寻找终止符。接口的失败契约不保证缓冲区含有可读的终止字符串，因此这条错误路径没有安全保证，可能读取未初始化数据或越界。

这是基于接口契约的静态发现；没有故意触发越界读取或声称已复现崩溃。Rust 版使用初始化缓冲区并检查第一次返回零，没有照搬该错误路径。

## 性能与 Rust API 建议的对照

| 建议 | 上游情况 |
|---|---|
| 缓存同一 PID 的进程句柄 | 上游从早期已有 `pid_to_handle` map；Rust 当前逐句柄重复 OpenProcess，属于没有保留的优化 |
| 用 ObjectTypeIndex 提前过滤 | 上游同样逐个 DuplicateHandle、查询对象类型；并未实现这种早期过滤 |
| 避免重复查询已匹配进程名称/路径 | 上游先按 PID 收集文件集合，最后为每个进程构造一个结果；Rust 对同一 PID 多次查名和覆盖，属于本地结果收集方式造成的重复 |
| 首个匹配模块就停止 | 上游输出该进程占用的文件列表，必须继续收集多个模块/文件；不能把 Rust 的“每个 PID 只显示一次”优化原样用于上游 |
| 缓冲区增长设上限 | 上游倍增且有容量上限；Rust 改成精确所需大小，未保留容量上限。这里只做健壮性比较，没测量卡住或内存耗尽 |
| 原生路径类型 | 上游用 UTF-16 `wstring`，没有 Rust 转 UTF-8 的有损转换问题；Rust 应使用 OsString/PathBuf 或保留 UTF-16 |
| SafeHandle 所有权封装 | Rust 专属接口问题；上游使用 raw HANDLE 及手工释放，反而有真实的提前返回泄漏 |
| UNICODE_STRING 原始指针转换、记录边界 | 两边都信任内核结果并使用原始指针；上游并没有更完善的类型/范围封装。这属于底层 API 可维护性，不是已证明的恶意输入漏洞 |
| 调试配置包名、严格 Clippy | 属于 Rust 仓库自身配置，不是 PowerToys 移植来源问题 |
| 边界测试 | 当前上游已有 6 个 CLI mock 测试和 UI 测试，但 CLI finder 为 mock，不能覆盖扫描核心中的长路径、模块失败、进程记录遍历或线程超时问题 |

## 用户认可的整体流程与借鉴方向

本节保留实施前的讨论决定。当时尚未授权修改；之后用户已授权逐项实施、验证并提交，结果见上面的修复记录。

1. **保留核心流程**：目标验证与路径解析 → 文件句柄扫描和模块扫描 → 按进程汇总 → 展示及可选结束进程。无需整体重写。
2. **借鉴进程句柄复用**：一次扫描内缓存并复用已经打开的进程句柄，使用现成的拥有型句柄自动释放。缓存设计同时考虑进程退出及 PID 身份问题，不将 PID 当作永久身份。
3. **借鉴先匹配、后补显示信息**：先汇总已确认的匹配，再为每个匹配进程查询一次名称和可执行文件路径。显示信息查询失败时保留匹配，可标注信息不可用，不依赖另一份进程列表来决定是否丢弃已发现结果。
4. **借鉴文件与目录的明确语义**：文件目标做同文件匹配，目录目标允许子路径匹配。多路径输入及每个进程完整的占用文件列表是可选产品扩展，不作为本轮必要范围。
5. **根据 Rust 当前输出减少重复工作**：当前只需每个进程显示一次，避免重复插入和查询；如将来输出完整占用文件列表，再继续收集全部匹配。这不是直接照搬上游的提前停止规则。
6. **保留 Rust 的自动资源释放和显式错误表达**：完善拥有/借用边界，保留单项成功结果，记录不完整扫描，不参考上游把全部失败简单表示为空集合的做法。
7. **共同改进模块路径查询**：Rust 和当前 PowerToys 都会按模块文件名重新打开文件。建议改为查询已有内存映射对应的文件名；这是双方的改进方向，不是上游当前已实现的能力。
8. **不复制上游线程恢复方案**：保留对可能挂起的系统查询的关注，不照搬 detach 后取句柄或强制结束线程的实现。隔离方案在需要实施时单独评估。

实施优先级：先修复已确认的正确性问题，再采用上述句柄复用与汇总改进；健壮性上限和更大功能扩展放在后面。性能收益仍需测量。

## 验证范围与产物

独立 C++20 探针使用本机 MSVC，以 `/W4 /WX` 编译通过，包含从当前上游源码抽取的函数和进程遍历代码。验证结果：

1. 三条合成进程记录 1/2/3，上游循环返回 2/3：跳过第一条，保留最后一条。
2. 长路径重试进入当前进程模块查询 API（mock）。
3. 模块枚举失败后，进程句柄打开一次、关闭零次（mock）。
4. 上游前缀函数区分大小写，并尊重目录分隔符边界（直接函数调用）。
5. 本机 MSVC 线程 detach 后原生句柄为空（实际标准库行为）。

探针：[run-probe.py](./run-probe.py)、[生成的 C++](./probe.cpp)、[验证输出](./probe-output.txt)。

该次上游对照没有构建完整 PowerToys、运行它的 UI/CLI 测试、结束任何进程/线程、访问远程共享、测试认证泄露或进行性能测量。这是一份聚焦来源和相关实现的静态审查加可控探针验证，不是整个 PowerToys 的完整安全审计。该审查阶段两边生产源码均未修改。

探针包含从 Microsoft PowerToys 抽取的源码；版权与 MIT 许可见 [UPSTREAM-LICENSE](./UPSTREAM-LICENSE)。生成脚本依赖本地克隆位置，验证输出是当时版本的历史证据。
