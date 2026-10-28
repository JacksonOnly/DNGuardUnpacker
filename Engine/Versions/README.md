# DNGuard 格式描述

现代头部的字段顺序、描述符、LEH 和算法编号集中在独立的 `ModernVersionProfile` 实现。历史类名记录格式最初验证的样本版本；解析器实际按头部、密钥及数据块校验选择格式，不读取运行库文件版本。

| 文件 | 布局 |
| --- | --- |
| DNGuard4600Profile.cs | 4.60，marker `0x001D007C`；密钥 W10、方法表 W7、独立 LEH 字段顺序与算法编号 |
| DNGuard4700_4800Profile.cs | 4.70/4.80，共用 marker，通过块长度验证区分两种布局 |
| DNGuard4922Profile.cs | 4.9.2.2，链式头部 |
| DNGuard493Profile.cs | 4.9.3.0，与 4.9.2.2/4.9.4.0 共用 marker，通过 key index 与块校验区分 |
| DNGuard494Profile.cs | 4.9.4.0，与 4.9.2.2 共用 marker，通过 key index 与块校验区分 |
| DNGuard4960Profile.cs | 4.9.6.0，链式头部；另已验证 DNG_Unknown_04 的双字节方法表反馈 / 字节 token 偏移变体 |
| DNGuard4970Profile.cs | 4.9.7.0，链式头部，与 4.96 共用 marker，密钥位于 W14；已验证 Single/Application 模式 |
| DirectHeader124FeedbackProfile.cs | 非链式 124 字节头；方法表两字节反馈，原始 token 字节偏移；由唯一静态字段签名约束 token 掩码 |
| DirectHeader112GroupedProfile.cs | 非链式 112 字节头；LEH 中 EH 大小、局部变量数、方法长度分别位于 0、2、4 字节；已验证外部方法块及算法候选 |

4.60 的验证目标 SHA-256 为 `565791896799CC75F2207F09F26469A263148725C95EC34FE179B61B48A8A45A`。其运行库文件版本与保护格式不一致，须由头部及密钥校验选择布局。`modern4600-regression INPUT` 覆盖 12 个算法编号、295 个方法记录、132 个代理、局部变量/EH 和损坏密钥/方法块拒绝；未覆盖的算法编号继续拒绝。`unpack` 同步输出 `OUTPUT.config`，保留原 EXE 配置中的服务器地址和 CLR 启动设置。

4.97 的验证样本为 `样本/DNG_HVM4970/TMFX_Client.exe`（SHA-256 `8E568AE6904A962E4452426C72D98D1A7D9F3772FE8E67F8D49149C8BA80B96D`）：已覆盖 12 个算法编号、局部变量/EH、代理、成对 token、加密字符串、资源和 16 个随包程序集。运行 `dotnet run --project Lab/tests/EngineTests -- modern4970-regression 样本/DNG_HVM4970/TMFX_Client.exe` 验证头部、算法向量和损坏输入拒绝；运行 `verify INPUT OUTPUT` 验证完整输出。4.97 的嵌入方法块地址变换尚无样本验证，该 profile 会拒绝此模式，保留已有版本的解析路径。

先运行 `probe INPUT --deep --report layout.json` 检查现有格式是否可自动复用。探测会尝试通过校验和恢复链式头、定位方法块并验证已知算法候选。确有新字段或新包络时，新建按格式命名的 profile，填写头部索引、LEH 偏移、描述符算法映射，并在 `ModernVersionRegistry.Profiles` 注册。注册表检查 marker+key index 冲突；共享 marker 通过密钥索引与块验证区分。未知密码算法仍需实现和验证，修改版本字符串不能增加兼容性。

公共方法解析、算法实现、运行时辅助代码清理位于 `Engine/Modern`，token 处理位于 `DNGDecrypter.SharedTokens.cs`，探测位于 `Engine/Layouts`。`DNGDecrypter.cs` 保留共享状态。历史 104/108/112/124/128/152/156/160 字节头位于 `Engine/Legacy`，按 `LegacyLayoutKind` 和字段校验选择，已有读取顺序保持；没有样本验证的分支仍不能宣称覆盖。

4.93、4.94、4.96 的方法明文均先进行 IL/操作数/分支/栈校验，原编号映射不通过时才尝试唯一有效的已有算法候选。4.96 的方法表反馈与 token 偏移分别恢复；`DNG_Unknown_05` 覆盖单字节反馈/右移偏移、单字节反馈/原始字节偏移以及双字节反馈/原始字节偏移。基类构造函数推导的不同 token 掩码不写死在 profile 中。具体通过范围见 `Lab/reports/026-corpus-progress-20261008.md`，不能由 profile 名称推断整版本完全支持。

`UtilityIntegration.dll` 进一步覆盖首方法为静态工具方法、构造函数位于后续元数据行的情况：首个已知明文校验失败时，只从受限的短基类构造函数及首方法完整 IL 校验推导唯一 token 掩码；不使用样本常量。历史 104/112 字节标准头的表前缀与压缩描述符变体由整表约束选择，保留原有大模块 28 位地址规则。新增通过及负向验收见 `Lab/reports/027-legacy-tables-and-later-token-salt-20261008.md`。

验证涵盖嵌入/外部/Single EXE、x86/x64、兼容级别、匿名保护和源码再编译。静态 Huffman 模块扫描根据 PE 和压缩流校验提取，不依赖相邻运行库的版本。完整覆盖以实际回归报告为准；仅识别头部、仅通过算法候选或缺少某种模式的样本，均不能宣称完整兼容。早期内联 token 的异或计数格式已验证构造函数成员引用，直接 RID 代理格式已验证目标、地址及签名，部分方法算法仍未知。

名称和擦除类型恢复独立放在 `Lab/SourceExporter/Recovery`，只处理导出用的临时程序集副本。`recovery-map.json` 区分原名证据、用途推断、可读替代名；没有一致证据的类型保留 `object`。不要为通过编译而修改导出的业务代码。
