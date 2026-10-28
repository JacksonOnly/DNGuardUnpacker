using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace DNGuard_Unpacker
{
    internal static partial class Program
    {
        public static string path;
        public static bool ShouldPrint = false;
        public static ModuleDefMD module;

        private static int Main(string[] args)
        {
            try
            {
                ConsoleLog.Configure(ref args);
                if (args.Length >= 2 && args[0] == "recover-types")
                {
                    if (args.Length != 2 && !(args.Length == 4 && args[2] == "--source-exporter"))
                        throw new ArgumentException("用法：recover-types 已脱壳文件 [--source-exporter 文件]");
                    SourceExportLauncher.RecoverTypes(SourceExportLauncher.Resolve(args.Length == 4 ? args[3] : null), Path.GetFullPath(args[1]));
                    return 0;
                }
                if ((args.Length == 2 || (args.Length == 3 && args[2] == "--rename-all")) && args[0] == "rename")
                {
                    RenameOutputInPlace(args[1], args.Length == 3);
                    return 0;
                }
                if (args.Length == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help"))
                { ConsoleLog.Help(); return 0; }
                if (args.Length >= 3 && args[0] == "source")
                {
                    string explicitExporter = null;
                    bool asyncSource = false, pruneSource = false;
                    bool renameSource = false, missingReferences = false;
                    var referenceDirectories = new List<string>();
                    for (int i = 3; i < args.Length; i++)
                    {
                        if (args[i] == "--source-exporter" && explicitExporter == null && i + 1 < args.Length) explicitExporter = args[++i];
                        else if (args[i] == "--async" && !asyncSource) asyncSource = true;
                        else if (args[i] == "--prune-empty" && !pruneSource) pruneSource = true;
                        else if (args[i] == "--rename-all" && !renameSource) renameSource = true;
                        else if (args[i] == "--allow-missing-references" && !missingReferences) missingReferences = true;
                        else if (args[i] == "--reference-dir" && i + 1 < args.Length) referenceDirectories.Add(Path.GetFullPath(args[++i]));
                        else throw new ArgumentException("Unknown, duplicated or incomplete source option: " + args[i]);
                    }
                    SourceExportLauncher.Run(SourceExportLauncher.Resolve(explicitExporter), Path.GetFullPath(args[1]), Path.GetFullPath(args[2]), asyncSource, pruneSource, referenceDirectories, missingReferences, renameSource);
                    return 0;
                }
                if (args.Length < 2 || (args[0] != "inspect" && args[0] != "unpack" && args[0] != "probe"))
                {
                    ConsoleLog.Help();
                    return 2;
                }
                path = Path.GetFullPath(args[1]);
                byte[] bytes = File.ReadAllBytes(path);
                byte[] externalMethods = null;
                StaticContainerExtractor.Result container = null;
                string before = Hash(bytes);
                string output = null;
                string containerPath = null;
                bool allowExecute = false;
                string sourceOutput = null, exporterPath = null;
                bool restoreAsync = false, pruneEmpty = false;
                bool recoverTypes = false;
                bool renameAll = false, allowMissingReferences = false;
                var sourceReferenceDirectories = new List<string>();
                string probeReport = null;
                bool deepProbe = false;
                if (args[0] == "unpack")
                {
                    if (args.Length < 3)
                        throw new ArgumentException("An explicit output path is required.");
                    for (int i = 3; i < args.Length; i++)
                    {
                        if (args[i] == "--allow-execute" && !allowExecute) allowExecute = true;
                        else if (args[i] == "--container" && containerPath == null && i + 1 < args.Length)
                            containerPath = Path.GetFullPath(args[++i]);
                        else if (args[i] == "--source" && sourceOutput == null && i + 1 < args.Length)
                            sourceOutput = Path.GetFullPath(args[++i]);
                        else if (args[i] == "--source-exporter" && exporterPath == null && i + 1 < args.Length)
                            exporterPath = args[++i];
                        else if (args[i] == "--async" && !restoreAsync) restoreAsync = true;
                        else if (args[i] == "--prune-empty" && !pruneEmpty) pruneEmpty = true;
                        else if (args[i] == "--recover-types" && !recoverTypes) recoverTypes = true;
                        else if (args[i] == "--rename-all" && !renameAll) renameAll = true;
                        else if (args[i] == "--allow-missing-references" && !allowMissingReferences) allowMissingReferences = true;
                        else if (args[i] == "--reference-dir" && i + 1 < args.Length) sourceReferenceDirectories.Add(Path.GetFullPath(args[++i]));
                        else throw new ArgumentException("Unknown, duplicated or incomplete option: " + args[i]);
                    }
                    output = Path.GetFullPath(args[2]);
                    if (string.Equals(path, output, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Input and output must be different files.");
                    if (File.Exists(output)) throw new IOException("Output already exists.");
                    if (containerPath != null && string.Equals(containerPath, output, StringComparison.OrdinalIgnoreCase))
                        throw new ArgumentException("Container and output must be different files.");
                    if (exporterPath != null && sourceOutput == null && !recoverTypes) throw new ArgumentException("--source-exporter requires --source or --recover-types.");
                    if ((restoreAsync || pruneEmpty) && sourceOutput == null) throw new ArgumentException("--async and --prune-empty require --source.");
                    if ((allowMissingReferences || sourceReferenceDirectories.Count != 0) && sourceOutput == null) throw new ArgumentException("--reference-dir and --allow-missing-references require --source.");
                    if (sourceOutput != null)
                    {
                        SourceExportLauncher.ValidateOutput(sourceOutput);
                        if (string.Equals(sourceOutput, output, StringComparison.OrdinalIgnoreCase) ||
                            output.StartsWith(sourceOutput.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                            throw new ArgumentException("Binary output must be outside the fresh source directory.");
                        exporterPath = SourceExportLauncher.Resolve(exporterPath);
                    }
                    else if (recoverTypes) exporterPath = SourceExportLauncher.Resolve(exporterPath);
                }
                else if (args[0] == "probe")
                {
                    for (int i = 2; i < args.Length; i++)
                    {
                        if (args[i] == "--deep" && !deepProbe) deepProbe = true;
                        else if (args[i] == "--report" && probeReport == null && i + 1 < args.Length)
                        {
                            probeReport = Path.GetFullPath(args[++i]);
                            if (File.Exists(probeReport) || Directory.Exists(probeReport)) throw new IOException("探测报告路径已经存在。");
                        }
                        else throw new ArgumentException("probe 选项未知、重复或缺少参数：" + args[i]);
                    }
                }
                else if (args.Length != 2) throw new ArgumentException("inspect requires exactly one input.");
                bool managedInput = ContainerExtractor.IsManaged(bytes);
                if (containerPath != null)
                {
                    if (!managedInput) throw new ArgumentException("--container is for an extracted managed module.");
                    container = StaticContainerExtractor.Extract(File.ReadAllBytes(containerPath));
                    if (!bytes.SequenceEqual(container.Module))
                        throw new InvalidDataException("The supplied container does not contain this exact managed module.");
                    externalMethods = container.Methods;
                    Console.WriteLine("CONTAINER matched externalMethods=" + externalMethods.Length + " source=" + containerPath);
                }
                else if (managedInput && (args[0] == "unpack" || args[0] == "probe"))
                {
                    container = CompanionContainer.Find(path, bytes, out containerPath);
                    if (container != null)
                    {
                        externalMethods = container.Methods;
                        Console.WriteLine("CONTAINER matched externalMethods=" + externalMethods.Length + " source=" + containerPath);
                    }
                }
                if (!managedInput)
                {
                    Console.WriteLine("INPUT sha256=" + before);
                    try
                    {
                        var extracted = StaticContainerExtractor.Extract(bytes, path);
                        container = extracted;
                        bytes = extracted.Module;
                        externalMethods = extracted.Methods;
                        Console.WriteLine("CONTAINER static " + extracted.Machine + " headerRaw=" + extracted.HeaderOffset.ToString("X8") + " headerBytes=" + extracted.HeaderSize + " moduleBytes=" + bytes.Length);
                    }
                    catch (NotSupportedException) when (ContainerExtractor.IsNativeDll(bytes))
                    {
                        var native = NativePeInfo.Read(bytes);
                        Console.WriteLine("NATIVE " + native.Architecture + " 原生 DLL；CLR 目录 RVA=0x" + native.ClrRva.ToString("X8") +
                            "；导出=" + (native.Exports.Count == 0 ? "无具名导出" : string.Join(",", native.Exports)));
                        if (args[0] == "inspect") return 0;
                        throw new NotSupportedException(native.IsVmRuntime
                            ? "输入为原生 VMRuntime 支持库，不是 .NET 托管程序集；没有可提取的托管负载。请对调用它的托管 DLL 执行 unpack；--allow-execute 不会将原生 DLL 转成 C# 程序集。"
                            : "输入为原生 DLL（CLR 目录为 0），未找到受支持的托管负载；请使用待恢复的 .NET 程序集或包含托管负载的容器。");
                    }
                    catch (NotSupportedException) when (args[0] == "unpack" && allowExecute)
                    {
                        Console.WriteLine("CONTAINER explicit legacy x86 execution requested");
                        bytes = ContainerExtractor.Extract(path);
                        Console.WriteLine("CAPTURED bytes=" + bytes.Length);
                    }
                    catch (NotSupportedException error) when (args[0] == "inspect" &&
                        error.Message.StartsWith("No supported static Single EXE payload found.", StringComparison.Ordinal))
                    {
                        var native = NativePeInfo.Read(bytes);
                        Console.WriteLine("NATIVE " + native.Architecture + " 原生 EXE；CLR 目录 RVA=0x" + native.ClrRva.ToString("X8") +
                            "；未发现支持的 DNGuard 托管容器。");
                        return 0;
                    }
                }
                module = ModuleDefMD.Load(bytes);
                if (args[0] == "inspect" || ConsoleLog.Verbose || ConsoleLog.Legacy) Inspect(module, bytes);
                else Console.WriteLine("MODULE " + module.Name + " methods=" + module.GetTypes().Sum(t => t.Methods.Count));
                if (args[0] == "inspect") return 0;
                if (args[0] == "probe")
                {
                    var report = deepProbe ? DNGDecrypter.ProbeLayoutDeep(bytes, externalMethods) : DNGDecrypter.ProbeLayout(module, externalMethods);
                    Console.WriteLine("PROBE " + (report.Recognized ? "已识别布局：" + report.Layout : "尚无完整解析器") +
                        "；头长度=" + report.HeaderSize + "；密钥证据=" + report.Keys.Count + "；方法块候选=" + report.Blocks.Count);
                    foreach (var key in report.Keys) Console.WriteLine("PROBE 密钥 W" + key.KeyIndex + "；加密字段 W" + key.EncryptionIndex + "；RVA=0x" + key.KeyRva.ToString("X8"));
                    foreach (var block in report.Blocks) Console.WriteLine("PROBE 方法 RVA=0x" + block.MethodsRva.ToString("X8") + "；方法数=" + block.MethodsCount + "；表变换字节=" + block.TableXorLength);
                    if (report.Diagnostic != null) Console.WriteLine("PROBE " + report.Diagnostic);
                    if (report.DeepValidation != null)
                    {
                        var deep = report.DeepValidation;
                        Console.WriteLine("PROBE 深度校验=" + (deep.Succeeded ? "通过" : "失败") + "；方法数=" + deep.MethodsValidated + "；匿名字符串数=" + deep.AnonymousStringsValidated);
                        if (deep.Diagnostic != null) Console.WriteLine("PROBE " + deep.Diagnostic);
                    }
                    if (probeReport != null) { report.Write(probeReport); Console.WriteLine("SAVED " + probeReport); }
                    return report.Recognized && (!deepProbe || report.DeepValidation.Succeeded) ? 0 : 3;
                }
                bool preserveMetadata;
                bool plain = container == null && externalMethods == null && PlainManagedInput.IsReadable(module);
                if (plain)
                {
                    if (renameAll) throw new ArgumentException("未加密输入采用逐字节保留，不支持 --rename-all；请另用 rename 命令。");
                    preserveMetadata = true;
                    Console.WriteLine("RESULT kind=ReadableUnprotectedCopy 未检测到 DNGuard 保护证据；IL 校验通过，逐字节保留（不计为解密）。");
                }
                else module = RestoreModule(module, bytes, externalMethods, container, renameAll, out preserveMetadata);
                WriteOutput(module, container, path, output, before, containerPath, preserveMetadata, renameAll, plain ? bytes : null);
                Console.WriteLine("SAVED " + output);
                if (recoverTypes) SourceExportLauncher.RecoverTypes(exporterPath, output);
                if (sourceOutput != null) SourceExportLauncher.Run(exporterPath, output, sourceOutput, restoreAsync, pruneEmpty, sourceReferenceDirectories, allowMissingReferences, renameAll);
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine("ERROR " + error.GetType().Name + ": " + error.Message);
                if (ConsoleLog.Verbose || ConsoleLog.Legacy) Console.Error.WriteLine(error);
                return 1;
            }
            finally { if (module != null) module.Dispose(); Console.Out.Flush(); Console.Error.Flush(); Console.ResetColor(); }
        }

        
        private static ModuleDefMD RestoreModule(ModuleDefMD module, byte[] bytes, byte[] externalMethods,
            StaticContainerExtractor.Result container, bool renameAll, out bool preserveMetadata)
        {
            bytes = (byte[])bytes.Clone();
            try
            {
                var engine = new MethodsDecrypter(module, externalMethods);
                try { engine.Find(); }
                catch (InvalidDataException) when (externalMethods == null)
                {
                    externalMethods = DNGDecrypter.FindExternalMethodBlock(module, bytes);
                    if (externalMethods == null) throw;
                    engine = new MethodsDecrypter(module, externalMethods);
                    engine.Find();
                }
                if (!engine.Detected) throw new NotSupportedException("DNGuard runtime type not found.");
                engine.DecryptInternal(ref bytes);
                module.Dispose();
                module = ModuleDefMD.Load(bytes);
                engine = new MethodsDecrypter(module, externalMethods);
                if (container != null) container.ApplyPresentationResources(module);
                engine.Find();
                engine.Decrypt();
                StringDecrypter.Decrypt(module, engine.decrypter);
                var decrypter = (DNGDecrypter)engine.decrypter;
                int fakeTypes = decrypter.RemoveProvenFakeTypes(engine.InitializeMethod);
                if (fakeTypes != 0) Console.WriteLine("CLEANUP proven fake type metadata=" + fakeTypes);
                if (!decrypter.IsModernLayout)
                {
                    int invalidMethods = InvalidMethodsFinder.RemoveUnreferenced(module);
                    if (invalidMethods != 0) Console.WriteLine("CLEANUP invalid methods=" + invalidMethods);
                }
                decrypter.RemoveModernHelpers();
                RemoveStartup(module, engine.InitializeMethod);
                RemoveUnusedRuntime(module, engine.RTType);
                if (!decrypter.IsLegacy112Layout)
                {
                    NormalizeEntryPointName(module);
                    int defaults = NormalizeOptionalConstants(module);
                    if (defaults != 0) Console.WriteLine("NORMALIZE optional UInt32 constants=" + defaults);
                    int asyncReturns = NormalizeAsyncReturnTypes(module);
                    if (asyncReturns != 0) Console.WriteLine("NORMALIZE async Task returns=" + asyncReturns);
                    int generatedReturns = NormalizeGeneratedReturnTypes(module);
                    if (generatedReturns != 0) Console.WriteLine("NORMALIZE generated reference returns=" + generatedReturns);
                    int memberNames = renameAll ? MemberNameNormalizer.RunAll(module) : MemberNameNormalizer.Run(module);
                    if (memberNames != 0) Console.WriteLine("NORMALIZE member names=" + memberNames);
                }
                else Console.WriteLine("PRESERVE legacy112 signatures, names, constants and metadata tokens");
                ValidateMethodBodies(module, decrypter);
                preserveMetadata = decrypter.IsLegacy112Layout;
                return module;
            }
            catch { module.Dispose(); throw; }
        }

    }
}
