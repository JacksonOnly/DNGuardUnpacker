using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

namespace DNGuard_Unpacker
{
    internal static partial class Program
    {
        
        private static void RenameOutputInPlace(string input, bool renameAll = false)
        {
            input = Path.GetFullPath(input);
            byte[] original = File.ReadAllBytes(input);
            string temporary = input + "." + Guid.NewGuid().ToString("N") + ".tmp";
            string backup = input + ".before-rename-" + Guid.NewGuid().ToString("N") + ".bak";
            try
            {
                using (var target = ModuleDefMD.Load(original))
                {
                    int count = renameAll ? MemberNameNormalizer.RunAll(target) : MemberNameNormalizer.Run(target);
                    Console.WriteLine("NORMALIZE member names=" + count);
                    if (count == 0) return;
                    var expected = target.GetTypes().SelectMany(t => t.Fields.Select(f => f.FullName)
                        .Concat(t.Methods.Select(m => m.FullName))).ToArray();
                    if (target.IsILOnly)
                    {
                        var options = new ModuleWriterOptions(target);
                        options.MetadataOptions.Flags = GetWriterMetadataFlags(true);
                        target.Write(temporary, options);
                    }
                    else
                    {
                        var options = new NativeModuleWriterOptions(target, true) { KeepExtraPEData = true, KeepWin32Resources = true };
                        options.MetadataOptions.Flags = GetWriterMetadataFlags(true);
                        target.NativeWrite(temporary, options);
                    }
                    using (var reloaded = ModuleDefMD.Load(temporary))
                        if (!expected.SequenceEqual(reloaded.GetTypes().SelectMany(t => t.Fields.Select(f => f.FullName)
                            .Concat(t.Methods.Select(m => m.FullName)))))
                            throw new InvalidDataException("Renamed metadata did not survive serialization.");
                }
                if (Hash(File.ReadAllBytes(input)) != Hash(original)) throw new IOException("Input changed during renaming.");
                File.Replace(temporary, input, backup);
                Console.WriteLine("SAVED " + input);
                Console.WriteLine("SAVED backup=" + backup);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
}
