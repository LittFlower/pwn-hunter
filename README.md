# PwnHunter

面向线下 CTF 的 IDA 9.x Pwn 漏洞候选点扫描插件。核心分析完全在本机执行，不依赖网络或大模型。默认使用有时间和函数数量预算的快速扫描，避免在静态链接程序上反编译整个 IDB。

当前版本通过 Hex-Rays ctree、类型信息和 microcode CFG 提取统一 IR，再由可独立测试的规则引擎分析：

- 可控或非常量格式化字符串
- 字面量 `printf`/`fprintf`/`sprintf`/`snprintf`/`asprintf`/`syslog` 族格式中的窄字符 `%s` 源读取：支持顺序参数、`*` 宽度、POSIX `$` 位置参数、静态精度和动态精度；无精度读取要求源对象存在 `NUL`，`%.Ns` 按 N 与源容量比较，`%.*s` 则联合精度类型、reaching 定义和路径 guard，只有证明 `0 <= precision <= available_capacity` 才消除告警；最大读取表达式可穿透包装函数，`v*` 的不透明 `va_list` 不做 ABI 猜测
- `read`、`recv`、`memcpy`、`fgets` 等长度与栈/堆对象容量不匹配
- `gets`、`strcpy`、`sprintf` 等无界写入
- `scanf` 的无宽度 `%s`/`%[` 以及没有为 `NUL` 预留空间的宽度；兼容 glibc 2.38+ 的 `__isoc23_scanf`/`fscanf`/`sscanf` 与 `__isoc23_strto*` ABI 别名
- `read`/`recv`/`iconv`/`strncpy` 后缺少 `NUL`，并把 `strlen`、`strcmp` 等消费点跨包装函数关联成一条链；原始输入的 may-unterminated 状态会随 `WriteEffect` 穿透自定义读取包装器，glibc x86-64 栈保护函数中只有紧邻数组、来自 `FS:0x28` 的 canary 确定提供低位零哨兵时，精确满写才按机器级可终止路径消除告警，超长写入仍会覆盖哨兵并报告
- `strcpy`/`stpcpy` 的源、`strcat` 的目标与源以及 `strdup` 的源均按完整 C 字符串读取建模，并覆盖 clang/glibc 的 `__strcpy_chk`/`__stpcpy_chk`/`__strcat_chk` 变体；恰好填满对象的原始输入会在复制/分配处报告越界读，读取效果可穿透自定义包装函数；fortify 对象大小也会穿透写入摘要，可信容量抑制目标告警，`SIZE_MAX` 或受污染容量则回退为普通无界写
- `strnlen`/`strndup` 的有界 C 字符串扫描，以及 `strncmp`/`strncasecmp` 的双源提前终止语义：显式 `n`、路径 guard、符号堆分配乘积和另一侧已证明字符串的 `NUL` 位置都可独立形成安全上界；最大读取限制与 peer 上界会穿透包装函数，只有所有上界证明都超过源对象时才报告 `STR-001`
- `__sprintf_chk`/`__vsprintf_chk` 的目标写与对象大小语义：激活检查在目标写穿前失败关闭，`SIZE_MAX` 或受污染容量回退为普通 `sprintf` 无界写；字面量格式和可映射变参随 `WriteEffect` 穿透包装器，使数值格式继续使用有限上界，纯文本及 `%%` 则计算精确输出字节数，同时不会隐藏格式中 `%s` 的源端终止性检查；当被调函数的所有返回路径都是有限字符串字面量时，还会把最大返回长度经局部赋值传播到 `%s`，只要存在未知返回路径就保守撤销该证明
- `strtok` 的 C 字符串读取与状态化污点：非空输入按语句顺序重置会话，`strtok(NULL, ...)` 续 token 保留首次输入来源；来源可穿透局部别名、格式包装器和返回值摘要，干净重置不会继承旧会话
- `strtof`/`strtod`/`strtold` 的 NUL 扫描与条件返回污点，使外部浮点文本经整数转换后仍能关联到分配、索引和 I/O 长度；常量文本转换不会被升级为攻击者来源
- `memcpy` 的目标越界与源对象越界，`write`/`send`/`fwrite` 等输出 API 及 `memchr`/`memrchr` 搜索 API 的源对象越界，以及独立协议 `message`/`length` 字段错配；源读取效果可穿透多层包装函数，也能把 `write(source + done, chunk)`、`done += chunk`、`done < total` 形式的分块输出循环汇总为 `source[0..total)`；动态长度会利用调用路径上界，`fread`/`fwrite` 的 `size * count` 则逐因子求界后相乘，不会把最小因子界误当成总字节数；固定字符串字面量按编码字节加结尾 `NUL` 计算真实存储容量
- `memcmp`/`bcmp` 两个源对象的完整定长读取边界，包括常量栈对象、符号堆容量和跨包装函数的双 `ReadEffect` 摘要；与另行建模、遇到任一 `NUL` 可提前停止的 `strncmp` 保持语义隔离
- `writev`/`pwritev`/`pwritev2` 与 `readv`/`preadv`/`preadv2` 的双向聚合 I/O：同时校验 `iovec` 描述符数组与每个 `iov_base[0..iov_len)` payload，输出方向检查源越界和短读尾部泄露，输入方向检查目标写穿、外部输入污点及满对象后 C 字符串消费；效果可穿透自定义包装器并保留文件句柄来源，固定 `/proc/self/*` 读取不会被误标为 hostile。对 Hex-Rays 把栈上 `iovec[]` 拆成 UDT、指针和整数局部变量的情况，只在栈槽连续、类型严格匹配且字段存在唯一 reaching definition 时重建后续项；无效 `iovcnt` 与常量 `sum(iov_len) > SSIZE_MAX` 按 Linux 调用前失败语义排除不可达 payload
- `sendmsg`/`recvmsg` 与 `sendmmsg`/`recvmmsg` 的 Linux 消息 I/O：按 32/64 位 ABI 恢复 `msghdr`/`mmsghdr`，分别检查 header 读取、批量 `msg_len` 回写、`msg_name`、`msg_control` 和嵌套 `msg_iov`；接收方向继续传播 payload/地址/控制数据污点和未终止状态，效果可穿透只接收 message 指针的包装器并保留内部 sink。模型遵循内核失败顺序：负的非空 `msg_namelen`、超限 `msg_iovlen`、聚合长度超过 `SSIZE_MAX` 先阻断不可达访问，地址长度按 128 字节 `sockaddr_storage` 截断，发送控制长度超过 `INT_MAX` 不读取用户控制区；批量调用区分仅 `sendmmsg` 将 `vlen` 截到 `UIO_MAXIOV`，`recvmmsg` 保留未截断计数
- glibc fortify 检查变体（包括 `__memcpy_chk`、`__read_chk`、`__fgets_chk`、`__strncpy_chk`、`__sprintf_chk`、`__snprintf_chk`）：可信对象大小有效时按“越界前终止”语义抑制不可达的目标写入、源读取、后续字符串消费和长度整数症状，同时保留检查允许执行路径上的源越界、输入污点及摘要效果；对象大小与未终止状态随读写摘要穿透自定义包装器，`SIZE_MAX` 或受污点时回退到基础 API 的保守模型；已识别 libc/fortify 的直接语义模型优先于二进制内可见实现，避免把 `__read_chk` 函数体再次展开成失去对象大小保护的普通 `read`；若导入符号的 Hex-Rays 原型遗漏 `__strncpy_chk` 第四参数，扫描前会补正该已知 ABI 类型，并只预反编译直接调用 fortify 的局部包装器及刷新其调用者，不扰动无关调用图的类型恢复
- 未初始化栈/`malloc` 对象的短读尾部泄露：识别按 `read`/`recv` 请求长度而非实际返回值执行的 `write`/`send`，同时排除 `calloc`、预初始化、分段填充、返回值长度、完整读取路径 guard，并让输出读取摘要穿透包装函数
- `malloc`/`calloc`/`realloc`/`reallocarray`/`aligned_alloc` 与 `mmap`/`mmap64` 返回对象的常量或符号容量；以唯一 reaching allocation 和仿射式证明 `malloc(n)` 后写入或读取 `n + 常量`、`calloc`/`reallocarray(count, width)` 后访问 `count * width + 常量`，并让分配效果穿透返回包装函数；覆盖指针偏移和地址保持别名，在分支重定义或尺寸变化时拒绝关联；映射容量按页取整并单独标记为 mapped storage
- 循环式 `read_exact(base + done, total - done)` 包装函数的总写入长度，并保留调用点范围保护
- 包装函数参数上的常量指针字节位移：`destination + N`、`source - N` 及多层组合会随读写/输入摘要保留，使调用者按剩余对象容量检查并报告对象起点之前的访问；动态位移不会被降级成零位移。IR 以 Hex-Rays 结果类型显式区分地址与标量，避免把 `size + N` 错当成对象内部地址
- 独立的跨函数标量表达式摘要：保留 `add/sub`、常量 `mul/shl`、cast、运算位宽和有符号性，可组合多层分配与 I/O 包装器；因此 `malloc(size + header)` 的回绕、常量调用点的真实堆容量以及 `read(dst, count * width)` 的调用前溢出都能在外层恢复。`read`/`recv` 等返回值区分“成功结果不超过请求长度”和负错误哨兵，不会把一次 4 KiB 读取泛化成任意接近 `SIZE_MAX` 的正数
- 输入错误返回值的专用 `ERR-001` 链：`read`/`recv`/`pread` 等 `-1` 契约及成功上界可穿透多层读取包装器，也可由无条件 `*out = (size_t)read(...)` 输出参数摘要继续穿透外层包装器并落到调用者的局部、全局或常量偏移记录字段。摘要还保留“输出仍为错误哨兵时包装器可能返回的状态常量”：调用方的 `status == 0`、`status >= 0` 或等价提前返回路径只有在排除全部错误状态时才消警，忽略状态、无效检查或把错误状态重映射成同一成功值时仍报告；直接 `return inner(...)` 可跨层保留关系，三元表达式、比较/布尔返回以及多个常量出口会在输出哨兵假设下求出有限状态集合，未知条件则合并两臂而不会冒充唯一映射。Hex-Rays 把 Call 排在其 Condition、受保护 body 或 Return 表达式之后遍历时，摘要与调用方分析都会恢复唯一匹配表达式的逻辑执行点；ARM64 的 W0 零扩展返回码会在调用方按实际位宽、符号性重新解释，`status >= 0` 被改写成符号位掩码比较后仍能正确消警。输出摘要保留原始语句位置，并按 CFG 判断其后是否在所有路径上被重写：已知只读调用、零长度写入和兄弟字段写入保留契约，精确或部分重叠写、以及接收该指针的未知调用会使契约失效；已完成分析且没有写效果的内部函数不会被误当成未知写入。只有观察到同位宽有符号结果写入明确无符号存储，并且该精确 reaching value 未经重定义或可能写穿的指针调用到达分配、复制、I/O 长度、聚合计数或数组下标时才报告；同对象兄弟字段的写入和 guard 不会误杀该链。`result < 0`、`count != SIZE_MAX` 等实际 sink 路径上的接受/拒绝 guard 会按有符号或无符号表示求值并消除告警，过晚检查、别名后的危险使用和显式 `(size_t)` cast 仍会命中；成功返回上界只消除不成立的正数 `INT-005`，失败转换仍由 `ERR-001` 保留，且专用告警会取代同一转换的普通 `INT-002`
- `ERR-001` 的合流与动态写穿补充：状态先写入局部或全局标量再于合流点返回时，已证明互补的 `if/else` 会合并两侧有限值；无条件默认值与后续可选覆盖保留二者，未覆盖的单分支定义仍保守退出关系证明。确定长度写入 API 额外区分“请求上限”和“必写下限”：无法证明 `memset(dst, 0, n)` 的 `n` 大于零时不得把未知长度冒充无界覆盖，只有字面量、类型一致的路径 guard、提前 `return`/noreturn 拒绝分支的继续路径补集，或未合流直接 CFG 边证明了正下界，并且每条后继路径都有重叠写时才清除契约；相关标量或字段重定义会撤销旧 guard，合取条件中未受影响的分量仍可保留。无符号值排除类型最小/最大值时可把 `!=` 收紧为边界区间，例如 `size_t n != 0` 推出 `n >= 1`；一般中间值不等式仍不猜测。must-write 属性与长度表达式可继续穿透包装器
- `ERR-001` 的 may-write/strong-write 分流：`read`/`recv`/`fread`/`getrandom` 等输入调用可能返回 0 或错误，`scanf` 可能完成零次转换，其他 bounded 格式/字符串写也只描述请求上限；这些效果继续传播污点、容量和包装器写摘要，但不能仅凭非零请求长度清除更早的错误输出。直接调用和多层包装器使用同一规则；`memset`/`memcpy` 等确定写入仍由 must-write 下界清除，接收目标指针且语义未知的调用则继续按保守别名写穿处理
- 动态循环里持续递增的栈数组索引：结合 CFG 回边、循环动态上界和缺失容量保护识别累计越界，同时排除固定小循环
- 跨函数全局记录 `{size, pointer}` 的分配容量，以及 `size + 正常量` 写回同记录指针的确定越界模式
- CFG 上的 may-free/must-free 生命周期固定点，以结构化位置身份区分宿主对象和载入字段，识别“先保存 next、再释放 current”的链表清理循环，并按真实调用顺序处理 `realloc`/`reallocarray`
- 全局 chunk 槽释放后未清空导致的可重复 UAF/Double Free 候选
- 保留间接调用目标表达式，并把悬挂全局对象关联到对象内函数指针调用汇点
- 整数截断、符号转换、分配及 I/O 长度乘法/左移溢出、无符号 `size + 正常量` 分配回绕和 `size - 常量` 下溢；传给分配、内存和 I/O API 的显式缩放统一使用调用前中间表达式的真实位宽与有符号性，递归计算 `add/sub/mul/shl` 区间；动态左移还验证移位量范围和有符号左操作数非负。`calloc`/`reallocarray` 的参数间隐式乘积由分配器检查，不产生整数告警，但参数内部预先执行的显式算术仍会分析；类型、路径 guard、cast、掩码、取模与 reaching 定义可证明宽化或受限运算安全，也能消除 Hex-Rays 把非负 unsigned 派生式打印成 signed 表达式造成的噪声；加法规则同样按实际运算位宽计算阈值；其他转换规则还利用输入 API 上界、仿射范围、`ssize_t` 的 `-1` 哨兵检查、无符号夹紧及 `calloc` + 有宽度 `scanf`；调用、赋值和返回保留 then/else 极性正确的 ctree 路径谓词，也能从提前 `return`/`exit` 的拒绝分支推导继续路径补集，并在 guard 依赖值或字段被重写后撤销证明
- 常量偏移记录字段与尾随内联数据区的字段敏感污点；动态索引或无法解析的别名仍保守回退为整对象污点，避免把同一连接记录中的请求字节、文件描述符和内部接收游标混为一谈
- `&&`、`||`、三元表达式的求值前置守卫，以及 `+=`、`|=` 等复合赋值的显式读改写 IR；未合流的单前驱 CFG 分支可从兄弟边恢复谓词极性，并证明经正返回值检查的 `recv(base + cursor, capacity - cursor)` 游标更新不会制造负长度
- 具有路径容量事实的常量内联越界写、可控索引无上界和有上界但缺少负数检查；识别“有符号窄值检查、无符号窄值索引全局表”的保护语义错位；只沿汇点前未被重写的值保持赋值关联 guard 与索引，不把合流前条件、析取条件或旧别名误当成值域证明
- 自定义输入、格式化输出、分配和释放包装函数的跨函数摘要，包括内联输出参数写及其条件污点来源
- `read`/`pread` 包装器保留输入句柄来源；未知句柄仍按外部输入处理，只有调用点可证明为固定 `/proc/self/*` 内核元数据时才消除运行时文件读取污点
- 跨函数全局堆对象容量，以及“写入自由链表 + 派生页 `munmap`”支撑的自定义释放器和索引全局槽悬挂候选
- 引用计数保护释放与同一对象 raw free 的协议不一致
- stripped 静态 glibc IRELATIVE thunk 的复制语义指纹（`memcpy`/`memmove`/`mempcpy` 类）
- stripped 静态运行库来源恢复：以 glibc/OpenSSL/Rust/Go 的源码路径、glibc libio 等特异源文件名和少量精确内部诊断为强种子，只沿直接 callee 方向传播，并保护直接交互入口
- 精确指纹匹配的高风险 gconv sidecar，并关联 `iconv_open` 描述符、`iconv` 调用点与外部输入存储

## 分析流程

快速扫描在调用 Hex-Rays 前完成候选排序：

1. 查找危险 libc/API 的调用者；
2. 查找菜单、索引、大小、登录等高信号交互字符串；
3. 扩展有限深度的 caller/callee 邻域；
4. 只反编译排序靠前且大小合理的函数；
5. 用 microcode 基本块和边建立 CFG，以打印后稳定的 ctree item index（EA 仅作兼容回退）把 then/else 极性正确的路径条件绑定到调用、赋值和返回语句；
6. 按内部调用依赖做脏调用者固定点，只重算受 callee 摘要变化影响的函数，生成效果摘要和全局堆对象事实后再运行容量、污点、整数和生命周期规则。

提取后的 IR 和规则引擎不依赖 IDA，可以直接通过 Python 单元测试。函数 IR 在当前 IDA 会话内增量缓存；修改函数原型或类型后可从插件菜单执行 `PwnHunter: Clear analysis cache`。

结果会按“规则、函数、危险调用、证据”聚合同型站点。`Sites` 列显示聚合数量，首地址用于跳转，其余地址仍保存在结果对象和 headless JSON 的 `related_eas` 中。

## 安装

开发模式使用符号链接，修改代码后重启 IDA 即可：

```shell
python3 install.py
```

部署到比赛机时复制插件：

```shell
python3 install.py --copy
```

默认安装至 `~/.idapro/plugins`。其他位置可使用：

```shell
python3 install.py --plugin-dir /path/to/ida/plugins
```

本机开发版本已经以符号链接安装。

## 使用

- `Ctrl+Shift+H`：有预算地快速扫描高价值候选函数
- `Ctrl+Alt+H`：只扫描光标所在函数
- `Ctrl+Shift+Alt+H`：深度扫描更大的非库函数集合
- 反编译窗口右键：`PwnHunter: Scan current function`

结果窗口按严重程度排序，双击条目跳转到对应地址。每个结果都显示容量、长度、危险调用和置信度。

快速扫描预算可用环境变量覆盖：

```shell
PWN_HUNTER_MAX_FUNCTIONS=300 \
PWN_HUNTER_MAX_SECONDS=30 \
PWN_HUNTER_CALLER_DEPTH=3 \
PWN_HUNTER_CALLEE_DEPTH=1 \
ida64 challenge
```

其他可用变量为 `PWN_HUNTER_MAX_FUNCTION_BYTES` 和 `PWN_HUNTER_MAX_STRING_SEEDS`。

## 测试

纯 Python 规则测试：

```shell
python3 -m unittest discover -s tests -v
```

预算扫描的 headless 回归：

```shell
PWN_HUNTER_RESULT="$PWD/tests/quick-result.json" \
  "/Applications/IDA Professional 9.4.app/Contents/MacOS/idat" \
  -A -c -L"$PWD/tests/quick-scan.log" \
  -S"$PWD/tests/quick_scan.py" \
  test_problem/darkheap/DarkHeap
```

全部 AWDP 语料的可复现基准（默认只提取服务 ELF；显式列入 manifest
的安全相关 sidecar 会一并提取）：

```shell
python3 tests/corpus_benchmark.py \
  --output tests/corpus-result.json \
  --max-functions 180 \
  --max-seconds 15

python3 tests/evaluate_accuracy.py
```

`AWDP-PWN-PHP.zip` 只有约 1.8 GB 的容器 tarball，没有可直接交给 IDA 的服务 ELF，因此脚本会明确跳过它，不会整体解压。

本地 CCB Final 2026 语料回归（会复制输入到临时目录，不修改题目旁的 IDB）：

```shell
python3 tests/ccb_benchmark.py \
  --root /Users/flower/ctf/ccb-final \
  --output tests/ccb-result.json

# 静态链接样本精度门禁：覆盖 HashArchiver 的全部 743 个候选函数
python3 tests/ccb_benchmark.py \
  --root /Users/flower/ctf/ccb-final \
  --case hash_archiver \
  --max-functions 800 \
  --max-seconds 60
```

当前冻结了 8 个独立确认的必达根因：HashArchiver 的动态桶遍历计数器写穿 288 元素栈数组、CreditMarket 的记录容量加常量堆溢出、HeroEditor 的循环读取包装函数栈溢出与分块预览源越界泄露、somewin 的自定义池释放后索引全局槽悬挂及其间接回调消费、someploy 的有符号检查与无符号全局表索引错位，以及 protokms 的失败路径 dangling slot。另把 somebox 的受限 shellcode 执行环境和 chall 的定长 camouflage/Rust 运行时 `/proc/self/maps` 读取作为 2 个已复核零候选负样本；该门禁只表示当前审计范围内不应产生内存漏洞告警，不构成对整个二进制的安全证明。

当前 CCB 门禁覆盖 8 个二进制，8 个必达位置全部命中，扫描结果也恰好只有这 8 个位置。
6 个正样本冻结了精确告警集合，额外位置也会使门禁失败；两个负样本要求零告警。
HashArchiver 的高预算扫描分析 743 个候选函数后仍只保留已确认的 `BUF-011`，静态 glibc
resolver/allocator/loader/libio 噪声会由来源证据和 IR 物理跨度证明消除；`somewin` 自带分配器中的
对齐元数据写与链表清理循环也不再形成候选。

本机 IDA 集成测试：

```shell
clang -O0 -g -fno-stack-protector \
  tests/fixtures/vulnerable.c -o tests/fixtures/vulnerable

PWN_HUNTER_RESULT="$PWD/tests/headless-result.json" \
  "/Applications/IDA Professional 9.4.app/Contents/MacOS/idat" \
  -A -c -L"$PWD/tests/ida-headless.log" \
  -S"$PWD/tests/headless_scan.py" \
  "$PWD/tests/fixtures/vulnerable"
```

该集成驱动会强制检查 `mmap_overflow` 的 `BUF-003`、
`dynamic_heap_off_by_one` 的 `BUF-012`、
`dynamic_heap_source_overread` 与 `output_wrapper` 的 `BUF-013`、
`short_read_tail_leak` 的 `INIT-002`、
`allocation_addition_wrap` 的 `INT-005`、
`allocation_multiplication` 的 `INT-003`、
`delete_callback_slot` 的 `LIFE-003` 与 `trigger_callback_slot` 的
`LIFE-007`，确保映射容量、Hex-Rays 间接调用目标提取和跨函数
retained-free 关联及消息摘要不会静默退化；其中
`sendmsg_payload_source_overread`、
`sendmsg_control_source_overread`、`sendmsg_header_overread`、
`recvmsg_payload_destination_overflow`、`recvmsg_wrapper` 与
`recvmsg_unterminated_printf` 冻结了真实 ctree 下的消息 header、嵌套
`iovec`、控制区、包装器和字符串状态行为，而 `sendmsg_exact_source`
作为精确长度负例必须保持安静。
`mmap/mmap64` 容量按 Linux CTF 常见的
4 KiB 页取整，`munmap` 因可能失败而进入 may-free 生命周期状态。
它还验证同一伪代码地址附近的 ctree 节点不会发生守卫串绑：两个槽写入必须
保留合取守卫，`calloc` 赋值必须保持无守卫，`else` 分支的动态索引写必须
取得取反后的 `< capacity` 谓词。fixture 还覆盖短路 `&&` 中只在上界成立后
执行的动态读取，以及在已检查索引上执行 `+=` 后必须撤销旧 guard 并报告越界。
它还要求真实 Hex-Rays IR 保留 `malloc(size)` 与后续
`read(..., size + 1)` / `write(..., size + 1)` 的符号关系，并让后一读取
穿透 `output_wrapper`，同时不会把 `mmap` 的页内余量误报为同类越界。
`short_read_tail_leak` 必须报告固定长度输出泄露，具有完整读取等值 guard 的
`checked_full_read_output` 则必须保持安静。
真实 32 位 `allocation_addition_wrap` 必须报告 `size + 32` 回绕，而带有
`size <= UINT_MAX - 32` 继续路径证明的 `checked_allocation_addition` 不得告警。
`allocation_multiplication` 的 64 位显式乘法必须保留 `INT-003`，而
`safe_narrow_calloc_product` 的 32 位因子在 64 位 size_t 中必须证明可容纳。
非分配长度也使用同一证明：32 位 `count * 16` 的
`unchecked_io_length_product` 必须报告，先宽化为 size_t 的
`safe_wide_io_length_product` 必须保持安静。
动态左移 fixture 还会直接检查 Hex-Rays 保留了 32 位 `shl`：未约束的
`count << shift` 必须报告，而 `shift <= 4` 且先把 count 宽化到 size_t 的
版本不得告警。有符号乘法按 `LONG_MIN..LONG_MAX` 而非无符号最大值判断，
`0 < count <= 1024` 的安全路径同样必须被证明。
checked allocator 对照会确保 64 位 `calloc(count, 16)` 的隐式乘积不产生
`INT-003`，但 `calloc(1, count * 16)` 的调用前显式乘法仍由单元门禁覆盖。
真实 `reallocarray(count, 16)` 后写入 `count * 16 + 1` 必须报告 `BUF-012`，
精确填充保持安静；`aligned_alloc(16, 32)` 后读取 64 字节必须报告 `BUF-003`。
fortify fixture 还会冻结三类语义：有效目标容量必须抑制必然终止后的目标
越界，禁用检查的 `SIZE_MAX` 必须回退并报告目标越界，而检查允许执行的
源对象越读仍必须报告。C23 `scanf` ABI 别名必须继续归一化为 `scanf`，其
输出污点与长度传播由稳定 IR 单元门禁冻结；用作内存地址的聚合指针 cast
不得被误判成 `INT-001`。
真实 `__strncpy_chk` 对照进一步要求对象大小穿透自定义包装器：请求长度
大于可信容量时，目标写入与发生在检查之后的源读取均不可达；检查允许执行
时仍报告源对象越读，`SIZE_MAX` 则回退并报告目标越界。恰好写满目标后交给
`strlen` 的路径还必须保留 `STR-001`，且 IDA 中不完整的三参数导入原型必须
在提取 IR 前补成四参数 ABI。
真实 `__read_chk` 对照还要求允许执行的精确满写经自定义包装器传播到
`strlen` 并报告 `STR-001`；请求长度大于可信对象大小时必须在读取前失败关闭，
即使对象先前已有未终止状态，后续字符串消费也不可达。无调试信息副本同样
必须保留包装器的四参数调用。AWDP Catchme 则冻结相反的布局证明：五个 8
字节输入数组都紧邻 `FS:0x28` canary，精确写满后由 canary 的低位零终止，
不得产生五个重复的弱字符串告警。
真实有界字符串 fixture 还要求 `strnlen(buf, sizeof(buf) + 1)`、其包装器以及
无法由短 peer 提前终止的超长 `strncmp` 报告 `STR-001`；精确容量
`strnlen` 和与短字面量比较的 `strncmp` 必须保持安静。
真实 `memcmp` 对照分别冻结首源、次源和包装器中的 `BUF-007`，精确覆盖
两个对象的安全比较必须保持安静；`bcmp` 首源越界与 `memchr` 搜索上界也有
独立正例，精确容量 `memchr` 保持安静。相关 8 字节源先经真实输入写入，确保
Hex-Rays 保留数组边界，而不是把夹具退化为无法证明边界的地址化标量碎片。
真实 tokenizer 对照还要求包装器返回的 `strtok(NULL, ...)` 继续保留外部
输入来源并把格式串升级为高置信度；恰好填满对象且没有 `NUL` 的输入必须在
`strtok` 处报告 `STR-001`，而以非空干净输入重置后的 token 不得继承旧污点。
浮点转换对照要求外部文本经 `strtod -> size_t` 后控制 `read` 时报告
`BUF-004`，无 NUL 的完整对象读取在 `strtod` 处报告 `STR-001`；常量
`strtod("12.5", NULL)` 的长度对照不得产生缓冲区或整数告警。
无界字符串复制对照要求恰好填满源对象的原始输入在 `strcpy` 处报告
`STR-001`；预先清零且只读取 `capacity - 1` 字节的源对象必须保持安静。
字符串 fortify 包装器还要求可信对象大小在写穿前失败关闭，而同一路径把
对象大小设为 `SIZE_MAX` 时必须在外层调用点报告 `BUF-002`，并保留内部
`__strcpy_chk` 与包装器名称。
格式化字符串参数对照要求恰好填满对象的原始输入在无精度 `%s` 处报告
`STR-001`，效果穿透自定义输出包装器；`%.8s` 读取 8 字节对象必须安全，
`%.9s` 则必须报告并在证据中保留 `format_precision=9`。
动态精度对照还要求未约束或可能为负的 `%.*s` 报告 `STR-001`；调用点
同时证明 `0 <= precision <= capacity` 时必须保持安静，精度表达式与内部
格式 sink 均须穿透包装器摘要。
`__sprintf_chk` 对照要求可信对象大小抑制目标写告警，`SIZE_MAX` 经包装器
传入时则报告 `BUF-002`；纯字面量输出必须给出精确所需字节数，而同一
fortify 调用中的未终止 `%s` 源仍须独立报告 `STR-001`。
CCB HeroEditor 还冻结分块输出摘要：内部每轮至多输出 8 字节，但循环按
`source + done` 前进直到调用者给出的 `total`；调用路径只把预览长度限制到
48，而源栈对象只有 24 字节，因此必须在内部 `write` 处报告 `BUF-007`，并
与同函数中的包装读取栈溢出保持为两个独立根因。
常量位移包装器 fixture 还冻结三条边界：`read(destination + 24, 16)` 必须按
调用者剩余容量判断，双层 `write(source + 8, count)` 组合成 `source + 16`，
而 `destination - 1` 必须报告对象起点之前的写入；精确容量、零长度和动态
位移对照均保持安静。
标量摘要 fixture 则要求 `malloc(size + 16)` 包装器保留 64 位无符号加法，
外部 `size` 触发 `INT-005`，两层 `size + 8` / `size + 16` 组合恢复 32 字节
堆容量；`read(dst, count + 8)` 的 33 字节外层调用报告 `BUF-003`，精确
32 字节对照保持安静。直接来自 `read(..., 32)` 的有界成功返回不得被误报为
任意大正数溢出。
错误返回 fixture 还要求 `error_return_reader -> size_t -> error_return_allocator`
在未检查路径报告唯一 `ERR-001`，证据同时保留读取与分配包装器；
`count == SIZE_MAX` 的拒绝路径必须保持安静，也不得再附带普通 `INT-002`。
输出参数对照进一步冻结
`read -> *out -> outer wrapper -> record.count -> count + 16 -> malloc`：兄弟
`record.status` 的 guard 不得错误抑制 `ERR-001`，精确 `record.count == SIZE_MAX`
拒绝则必须消警；成功返回上界应抑制两个调用方中不成立的普通 `INT-005`。
状态关系对照再经过 `void output wrapper -> status wrapper -> returning wrapper`：
忽略返回状态的调用方必须报告 `ERR-001`，`status == 0` 的内联条件调用必须
保持安静；即使 Hex-Rays 的 ctree 访问次序把条件 Call 排在 then-body 之后，
也不得漏掉未检查路径或给已检查路径附带 `INT-005`。
条件状态对照继续把错误码映射成 `status < 0 ? -7 : 0` 和 `status < 0`：
两个忽略状态的调用方必须报告，`status != 0` 必须消警；ARM64 上 Hex-Rays
把 `status >= 0` 重写为 `(call & 0x80000000) == 0`，也必须按 32 位有符号
返回码证明错误路径不可达。单元测试还冻结晚于 Return/Condition 才访问 Call、
未知三元条件合并两臂、互补分支赋值在合流点合并、默认值加可选覆盖保留有限
集合，以及未覆盖的分支定义仍保守退出关系证明。
写穿对照要求包装器在错误输出之后执行 `memset(output, 0, sizeof(*output))`
时清除摘要和调用方告警，而只读 `memcmp` 必须保留摘要与 `ERR-001`；单元测试
另外冻结零长度写、兄弟字段、部分重叠、未知指针调用、已分析纯函数、嵌套包装器
以及“单分支覆盖仍保留、所有分支覆盖才清除”的 CFG 语义。动态写穿对照进一步
要求无下界的 `memset(output, 0, n)` 保留摘要和调用方告警，而 `n >= sizeof(*output)`
与固定全宽写组成的互补分支必须清除；同一 must-write 下界也经包装器摘要传播。
继续路径单元对照冻结提前返回/noreturn 补集、未标注兄弟边、复合拒绝条件的逐项保留、
相关长度重定义失效及三路 CFG；真实 IDA 对照还要求 volatile 长度在 guard 后
复合重定义时保留 `ERR-001`，识别 Hex-Rays 将三路源码折叠出的 `size_t != 0`，
并要求 guarded `abort` 后的无 guard 动态写只在正常返回路径形成摘要。
may-write 对照另外要求错误输出之后的直接 `read(output, sizeof(*output))`
及其 noinline 包装器都保留摘要和调用方 `ERR-001`，因为失败或零返回路径不会
修改旧哨兵；确定长度 `memset` 对照仍必须保持安静。

## 分析边界

当前函数内污点传播仍是流不敏感固定点分析，但会区分可解析的常量偏移字段和尾随内联区域；动态地址、动态索引或不确定别名仍回退为整对象污点。文件读取句柄只对精确白名单中的固定 `/proc/self/*` 元数据路径做可信证明，其他常量、未知或参数句柄仍保守地视为外部输入。生命周期分析已经区分 CFG 合流点的 may-free/must-free，但没有完整求解每条边上的谓词；调用、赋值和返回会保留 then/else 极性正确的 ctree guard，合流后的条件不自动视为成立。只有单前驱、未合流的直接 CFG 边可利用兄弟分支的 ctree 极性补全谓词。分析器与错误输出必写摘要只对提前 `return` 或已知 noreturn 调用推导拒绝分支 guards 合取的补集，并在相关标量、字段或 reaching alias 被重新赋值后撤销该证明。只有部分分支释放会使用 `LIFE-004/LIFE-005` 和中等置信度。`LIFE-006` 只在同一 reaching pointer load 同时存在引用计数保护释放和绕过保护的原始释放时报告所有权协议不一致。间接调用会保留目标表达式，但跨函数 `LIFE-007` 只在目标能回溯到已确认的 retained-free 全局根时报告；摘要层仍不猜测无法映射到参数、全局槽或常量的复杂所有权效果。

`vprintf`/`vsnprintf` 等 `va_list` 入口只保留格式串规则，不猜测 ABI 内的单个变参；普通可见变参中的动态精度则按有符号范围分析，负值依照 printf 语义视为未指定精度。

`INIT-002` 只在同一对象上存在唯一原始字节输入、输入请求与输出长度仿射等价且没有其他对象使用时报告；任何可能的预初始化或多段填充都会保守退出。因此它不会覆盖所有未初始化内存泄露，但不会把普通协议缓冲复用猜成确定泄露。

尚未实现：

- 完整的 microcode SSA 值域、边谓词和 SMT 约束求解
- 跨函数引用计数、所有权转移、自定义对象协议等完整语义模型
- 锁集合、线程入口和 TOCTOU 分析

核心扫描不需要本地大模型，比赛断网环境下直接可用。当前能确定性识别同一函数内、同一 pointer load 的引用计数释放协议不一致；需要跨函数别名或隐式所有权契约的业务级错误仍适合由本地大模型读取确定性分析生成的小型程序切片后做二次排序和解释，不应代替对象大小、污点和生命周期分析。
