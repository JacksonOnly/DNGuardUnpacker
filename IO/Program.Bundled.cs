using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

namespace DNGuard_Unpacker
{
    internal static partial class Program
    {
        private static byte[] RestoreBundledAssembly(string name, byte[] bytes, bool renameAll)
        {
            if (bytes.Length < 2 || bytes[0] != 0x4D || bytes[1] != 0x5A || !ContainerExtractor.IsManaged(bytes)) return bytes;
            using (var original = ModuleDefMD.Load(bytes))
            {
                bool protectedFile = original.GetTypes().Any(t => t.FullName.Contains("ZYXDNGuarder"));
                if (!protectedFile)
                {
                    try
                    {
                        var probe = new DNGDecrypter(original);
                        byte[] header = null;
                        protectedFile = Enumerable.Range(1, 99).Any(i => probe.GetStructSize(i * 4, ref header) == i * 4);
                    }
                    catch (InvalidDataException) { }
                    catch (dnlib.IO.DataReaderException) { }
                }
                if (!protectedFile) return bytes;
                Console.WriteLine("BUNDLED unpack=" + name);
                bool preserve;
                using (var restored = RestoreModule(original, bytes, null, null, renameAll, out preserve))
                using (var output = new MemoryStream())
                {
                    if (restored.IsILOnly)
                    {
                        var options = new ModuleWriterOptions(restored);
                        options.MetadataOptions.Flags = GetWriterMetadataFlags(preserve);
                        restored.Write(output, options);
                    }
                    else
                    {
                        var options = new NativeModuleWriterOptions(restored, true) { KeepExtraPEData = true, KeepWin32Resources = true };
                        options.MetadataOptions.Flags = GetWriterMetadataFlags(preserve);
                        restored.NativeWrite(output, options);
                    }
                    var result = output.ToArray();
                    using (var check = ModuleDefMD.Load(result))
                        if (check.Name != restored.Name || check.Assembly.FullName != restored.Assembly.FullName)
                            throw new InvalidDataException("Restored dependency identity changed: " + name);
                    Console.WriteLine("BUNDLED unpacked=" + name + " bytes=" + result.Length);
                    return result;
                }
            }
        }
    }
}
