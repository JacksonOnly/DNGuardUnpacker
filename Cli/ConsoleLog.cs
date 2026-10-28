using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace DNGuard_Unpacker
{
    internal sealed class ConsoleLog : TextWriter
    {
        private readonly TextWriter output;
        private readonly StringBuilder pending = new StringBuilder();
        private readonly bool error;
        private string lastLayout;
        internal static bool Verbose { get; private set; }
        internal static bool Legacy { get; private set; }
        internal static bool Quiet { get; private set; }
        public override Encoding Encoding => new UTF8Encoding(false);

        private ConsoleLog(TextWriter output, bool error) { this.output = output; this.error = error; }

        internal static void Configure(ref string[] args)
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            Legacy = Environment.GetEnvironmentVariable("DNG_LOG_FORMAT") == "legacy";
            Console.SetOut(new ConsoleLog(Console.Out, false));
            Console.SetError(new ConsoleLog(Console.Error, true));
            var remaining = new System.Collections.Generic.List<string>();
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--verbose") { if (Verbose) throw new ArgumentException("--verbose 不能重复。"); Verbose = true; }
                else if (args[i] == "--quiet") { if (Quiet) throw new ArgumentException("--quiet 不能重复。"); Quiet = true; }
                else if (args[i] == "--log-format")
                {
                    if (i + 1 >= args.Length || Legacy || args[++i] != "legacy") throw new ArgumentException("--log-format 仅支持 legacy。");
                    Legacy = true;
                }
                else remaining.Add(args[i]);
            }
            if (Quiet && Verbose) throw new ArgumentException("--quiet 和 --verbose 不能同时使用。");
            args = remaining.ToArray();
        }

        internal static void Help()
        {
            bool quiet = Quiet;
            Quiet = false;
            try
            {
            Console.WriteLine("DNGuard 静态脱壳工具");
            Console.WriteLine("用法：");
            Console.WriteLine("  UniversalUnpacker inspect 输入文件 [--verbose]");
            Console.WriteLine("  UniversalUnpacker probe 输入文件 [--deep] [--report 新建报告.json]");
            Console.WriteLine("  UniversalUnpacker unpack 输入文件 新建输出文件 [选项]");
            Console.WriteLine("  UniversalUnpacker source 输入文件 新建源码目录 [选项]");
            Console.WriteLine("  UniversalUnpacker rename 已脱壳文件  （原地修复成员名并备份）");
            Console.WriteLine("  UniversalUnpacker recover-types 已脱壳文件  （原地恢复类型并备份）");
            Console.WriteLine("选项：");
            Console.WriteLine("  --container 文件         提供原始 Single EXE 容器");
            Console.WriteLine("  --source 目录            同时导出源码");
            Console.WriteLine("  --recover-types          解包后恢复可证明的 object 类型");
            Console.WriteLine("  --source-exporter 文件   指定源码导出器");
            Console.WriteLine("  --rename-all             忽略反射名称保留（仍保留虚方法/序列化契约）");
            Console.WriteLine("  --reference-dir 目录     源码导出额外依赖目录，可重复指定");
            Console.WriteLine("  --allow-missing-references 缺依赖时仍导出源码，保留诊断，不保证可编译");
            Console.WriteLine("  --async                  还原源码中的 async/await");
            Console.WriteLine("  --prune-empty            清理源码中的无引用空方法");
            Console.WriteLine("  --allow-execute          显式允许旧式 x86 动态提取");
            Console.WriteLine("  --verbose                显示方法、节和数据头的详细诊断");
            Console.WriteLine("  --deep                   probe 同时校验方法、算法候选及匿名字符串");
            Console.WriteLine("  --quiet                  仅显示结果和错误");
            Console.WriteLine("  --log-format legacy      保留旧版输出，供已有脚本使用");
            }
            finally { Quiet = quiet; }
        }

        public override void Write(char value)
        {
            if (value == '\n') { Emit(pending.ToString().TrimEnd('\r')); pending.Clear(); }
            else pending.Append(value);
        }
        public override void Write(string value) { if (value != null) foreach (char c in value) Write(c); }
        public override void WriteLine(string value) { Write(value); Write('\n'); }
        public override void WriteLine() { Write('\n'); }
        public override void Flush() { if (pending.Length != 0) { Emit(pending.ToString()); pending.Clear(); } output.Flush(); }

        private void Emit(string line)
        {
            if (Legacy) { output.WriteLine(line); return; }
            if (line.StartsWith("LAYOUT "))
            {
                if (line == lastLayout) return;
                lastLayout = line;
            }
            bool detail = line.StartsWith("SECTION ") || line.StartsWith("IMPORT ") || line.StartsWith("STRUCT ") ||
                line.StartsWith("  W") || line.StartsWith("- Restored method ") || line.StartsWith("  Instrs:") ||
                line.StartsWith("  Locals:") || line.StartsWith("  Exceptions:") || line.StartsWith("RECORD ") || line.StartsWith("CANDIDATE ");
            if (detail && !Verbose) return;
            if (Quiet && !error && !line.StartsWith("SAVED ") && !line.StartsWith("SOURCE ") && !line.StartsWith("PROBE ")) return;
            if (line.StartsWith("SAVED ") || line.StartsWith("SOURCE "))
            {
                output.WriteLine((line.StartsWith("SAVED ") ? "[完成] " : "[源码] ") + line.Substring(line.IndexOf(' ') + 1));
                return;
            }
            if (line.StartsWith("- Restoring ")) line = Regex.Replace(line, @"- Restoring (\d+) methods", "[恢复] 正在恢复 $1 个方法");
            if (line.StartsWith("- Restored method ")) line = "[方法] 已恢复 " + line.Substring(18);
            if (line.StartsWith("  Instrs:")) line = line.Replace("  Instrs:", "  指令数：");
            if (line.StartsWith("  Locals:")) line = line.Replace("  Locals:", "  局部变量：");
            if (line.StartsWith("  Exceptions:")) line = line.Replace("  Exceptions:", "  异常处理：");
            if (line.StartsWith("PASS source-export ")) line = "SOURCE 导出完成 " + line.Substring(19);
            if (line.StartsWith("ERROR ") || line.StartsWith("PROBE ")) line = TranslateError(line);
            string[,] labels = {
                {"CONTAINER", "容器"}, {"CAPTURED", "提取"}, {"INPUT", "输入"}, {"MODULE", "模块"}, {"NATIVE", "原生"},
                {"RESOURCES", "资源"}, {"SECTION", "节"}, {"IMPORT", "导入"}, {"STRUCT", "数据头"},
                {"LAYOUT", "布局"}, {"CLEANUP", "清理"}, {"NORMALIZE", "归一化"}, {"PRESERVE", "保留"},
                {"STRINGS", "字符串"}, {"REMOVED", "移除"}, {"VALIDATED", "校验"}, {"WRITER", "写出"},
                {"OUTPUT", "输出"}, {"BUNDLED", "依赖"}, {"SAVED", "完成"}, {"SOURCE", "源码"},
                {"PROBE", "探测"}, {"ERROR", "错误"}, {"SYNC", "同步"}, {"ASYNC", "异步恢复"}, {"EMPTY", "空方法"}
            };
            for (int i = 0; i < labels.GetLength(0); i++)
                if (line.StartsWith(labels[i, 0] + " ")) { line = "[" + labels[i, 1] + "] " + line.Substring(labels[i, 0].Length + 1); break; }
            string[,] phrases = {
                {"explicit legacy x86 execution requested", "已显式允许旧式 x86 动态提取"},
                {"compact managed PE", "已生成紧凑托管 PE"}, {"native sections preserved", "已保留原生节"},
                {"legacy112 signatures, names, constants and metadata tokens", "历史 112 字节布局的签名、名称、常量及元数据 token"},
                {"inputSha256", "输入 SHA-256"}, {"optional UInt32 constants", "可选 UInt32 常量"},
                {"async Task returns", "异步 Task 返回类型"}, {"generated reference returns", "生成方法的引用返回类型"},
                {"retainedReferenced", "保留的被引用项"}, {"externalMethods", "外部方法字节"},
                {"headerBytes", "头长度"}, {"moduleBytes", "模块字节"}, {"headerRaw", "头文件偏移"},
                {"methodsRva", "方法 RVA"}, {"settings", "保护标志"}, {"methods", "方法数"},
                {"helpers", "辅助项"}, {"resource decoys", "资源占位项"}, {"invalid methods", "无引用无效方法"},
                {"replaced", "已替换"}, {"saved", "已保存"}, {"directory", "目录"}, {"runtime", "运行时"},
                {"entry point", "入口"}, {"matched", "已匹配"}, {"static", "静态"}, {"variant", "变体"},
                {"Win32 resource types", "Win32 资源类型"}, {"IL methods", "IL 方法"}, {"bytes", "字节"},
                {"sha256", "SHA-256"}, {"explicitStateMachines", "保留状态机"}, {"explicitDelegates", "显式委托"},
                {"renamedGeneratedFields", "生成字段重命名"}, {"embeddedDependencies", "内嵌依赖"},
                {"delegateSignatures", "委托签名"}, {"recoveredTypes", "恢复类型"}, {"recoveredNames", "恢复名称"},
                {"classicFrameworkReferences", "经典框架引用"}, {"candidates", "候选数"}, {"restored", "已恢复"},
                {"discovered", "发现数"}, {"removedCalls", "移除调用"}, {"removedDefinitions", "移除定义"}, {"report", "报告"},
                {"source", "来源"}, {"offset", "偏移"}, {"header", "记录头"}, {"tokens", "token 偏移"},
                {"RAW", "文件偏移"}, {"SIZE", "长度"}, {"alternate", "备用"}, {"standard", "标准"}
            };
            for (int i = 0; i < phrases.GetLength(0); i++)
                line = Regex.Replace(line, @"(?<![\w\\/])" + Regex.Escape(phrases[i, 0]) + @"(?==|$)", phrases[i, 1]);
            if (line.StartsWith("[容器] static ")) line = "[容器] 静态 " + line.Substring(12);
            if (line.StartsWith("[容器] matched ")) line = "[容器] 已匹配 " + line.Substring(13);
            if (line.StartsWith("[归一化] entry point ")) line = line.Replace("[归一化] entry point ", "[归一化] 入口 ");
            output.WriteLine(line);
        }

        private static string TranslateError(string line)
        {
            string[,] messages = {
                {"An explicit output path is required.", "必须指定新建输出文件的路径。"},
                {"Input and output must be different files.", "输入和输出必须是不同文件。"},
                {"Output already exists.", "输出文件已存在，请指定新路径。"},
                {"Unknown, duplicated or incomplete option:", "选项未知、重复或缺少参数："},
                {"Unknown, duplicated or incomplete source option:", "源码选项未知、重复或缺少参数："},
                {"inspect requires exactly one input.", "inspect 只接受一个输入文件。"},
                {"Container and output must be different files.", "容器和输出必须是不同文件。"},
                {"--source-exporter requires --source.", "--source-exporter 需要配合 --source。"},
                {"--async and --prune-empty require --source.", "--async 和 --prune-empty 需要配合 --source。"},
                {"Binary output must be outside the fresh source directory.", "二进制输出必须位于新建源码目录之外。"},
                {"DNGuard runtime type not found.", "未找到 DNGuard 运行时类型。"},
                {"No supported static Single EXE payload found. Input was not executed.", "未找到可静态提取的 Single EXE 数据。"},
                {"Application Mode method block is external. Unpack the original Single EXE, or supply --container ORIGINAL_EXE for this extracted module.", "应用模式的方法块位于容器中；请使用原始 Single EXE，或通过 --container 指定原始容器。"},
                {"Invalid modern 4.9 method block layout.", "现代布局的方法块格式校验失败。"},
                {"Invalid external modern method block.", "外部方法块格式校验失败。"},
                {"Failed to restore method", "方法恢复失败："},
                {"Invalid anonymous string at offset", "匿名字符串偏移无效："},
                {"Unknown anonymous-token call signature:", "匿名字符串调用签名尚未支持："},
                {"Invalid dummy value!", "代理方法标记校验失败。"},
                {"Unsupported modern cipher", "尚未支持的现代算法编号"},
                {"Unverified modern cipher ID", "尚未验证的算法编号"},
                {"Unknown modern method RID", "未知方法 RID="},
                {"Unsupported modern method table kind", "尚未支持的方法表类型"},
                {"Unsupported modern proxy target kind at RID", "代理目标的类型尚未支持，RID="},
                {"Invalid modern proxy record at RID", "代理记录校验失败，RID="},
                {"Invalid modern proxy marker at RID", "代理记录标记校验失败，RID="},
                {"Invalid modern proxy target at RID", "代理目标无效，RID="},
                {"Invalid modern local descriptor size at RID", "局部变量描述符长度无效，RID="},
                {"Invalid modern method offset at RID", "方法数据偏移无效，RID="},
                {"Invalid modern descriptor RVA", "方法描述符 RVA 无效："},
                {"Invalid modern proxy mapping at RID", "代理映射无效，RID="},
                {"Modern methods decompressed length mismatch.", "方法数据的解压长度不匹配。"},
                {"Truncated modern paired token.", "成对 token 数据被截断。"},
                {"Invalid modern HVM token table.", "方法 token 表无效。"},
                {"Invalid modern HVM token index.", "方法 token 索引无效。"},
                {"Invalid modern paired token index.", "成对 token 索引无效。"},
                {"Invalid modern HVM token kind.", "方法 token 类型无效。"},
                {"Ambiguous chained modern header.", "链式数据头存在多个有效候选。"},
                {"Modern key checksum mismatch.", "密钥校验和不匹配。"},
                {"External methods require Application Mode.", "外部方法块需要应用模式。"},
                {"No unique validated modern block layout.", "未找到唯一且通过校验的方法块布局。"},
                {"Invalid modern resource count.", "资源数量无效。"},
                {"Modern user-string heap outside module.", "字符串数据区超出模块范围。"},
                {"Modern block cipher requires complete 8-byte blocks.", "块算法需要完整的 8 字节数据块。"},
                {"Invalid DNGuard methods count or buffer length; the structure layout may be unsupported.", "方法数量或数据块长度无效；该布局可能尚未支持。"},
                {"The supplied container does not contain this exact managed module.", "指定容器中的托管模块与输入不一致。"},
                {"--container is for an extracted managed module.", "--container 仅用于已提取的托管模块。"},
                {"Configuration output already exists:", "配置输出已存在："},
                {"Bundled assembly collides with input/output:", "随包程序集与输入或输出路径冲突："},
                {"Bundled assembly output already exists:", "随包程序集输出已存在："},
                {"Bundled assembly staging hash differs.", "随包程序集暂存数据的哈希不一致。"},
                {"Input hash changed.", "输入文件的哈希发生变化。"},
                {"Unrestored runtime dependency:", "仍有未恢复的运行时依赖："},
                {"Unresolved IL operand in", "IL 操作数无法解析，方法："},
                {"Invalid restored IL stack in", "恢复后的 IL 栈校验失败，方法："},
                {"Unsupported Single EXE machine:", "尚未支持的 Single EXE 架构："},
                {"Container section outside input.", "容器节超出输入范围。"},
                {"Multiple validated Single EXE payloads; refusing an ambiguous selection.", "多个 Single EXE 模块通过校验，无法唯一选择。"},
                {"Multiple Huffman-packed managed payloads; refusing an ambiguous selection.", "多个 Huffman 托管模块通过校验，无法唯一选择。"},
                {"Invalid Single EXE compressed module header.", "Single EXE 压缩模块头无效。"},
                {"Invalid Single EXE Huffman frequency table.", "Single EXE 的 Huffman 频率表无效。"},
                {"Single EXE Huffman frequency sum mismatch.", "Single EXE 的 Huffman 频率总和不匹配。"},
                {"SourceExporter not found.", "未找到源码导出器。"},
                {"Source output already exists:", "源码输出路径已存在："},
                {"Build Lab/SourceExporter in Release, or supply --source-exporter PATH.", "请构建 Lab/SourceExporter 的 Release 版本，或通过 --source-exporter 指定路径。"},
                {"Source export failed; existing unpacked binary and diagnostic output are preserved.", "源码导出失败；已恢复的程序集及诊断输出已保留。"},
                {"Could not find file", "找不到文件"},
                {"Could not find a part of the path", "找不到路径"},
                {"Export directory already exists.", "源码目录已存在，请指定新目录。"}
            };
            for (int i = 0; i < messages.GetLength(0); i++) line = line.Replace(messages[i, 0], messages[i, 1]);
            if (line.Contains("匿名字符串偏移无效："))
                line = Regex.Replace(line, @" in (.+) \(target RID (\d+)\)\.", "；方法=$1，目标 RID=$2。");
            return line;
        }
    }
}
