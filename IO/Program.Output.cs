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
        private static void WriteOutput(ModuleDefMD module, StaticContainerExtractor.Result container,
            string input, string output, string inputHash, string containerPath, bool preserveMetadata, bool renameAll, byte[] exactBytes = null)
        {
            string directory = Path.GetDirectoryName(output);
            var bundledOutputs = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);

            string inputConfig = input + ".config";
            string outputConfig = output + ".config";
            if (File.Exists(inputConfig))
            {
                if (File.Exists(outputConfig) || Directory.Exists(outputConfig))
                    throw new IOException("Configuration output already exists: " + outputConfig);
                bundledOutputs.Add(outputConfig, File.ReadAllBytes(inputConfig));
            }
            if (container != null)
                foreach (var pair in container.BundledAssemblies)
                {
                    string name = pair.Key;
                    
                    if (container.BundledApplicationName != null &&
                        (name == container.BundledApplicationName + ".deps.json" || name == container.BundledApplicationName + ".runtimeconfig.json"))
                        name = Path.GetFileNameWithoutExtension(output) + name.Substring(container.BundledApplicationName.Length);
                    BundledFileNames.Validate(name);
                    string destination = Path.GetFullPath(Path.Combine(directory, name));
                    if (string.Equals(destination, output, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(destination, input, StringComparison.OrdinalIgnoreCase) ||
                        (containerPath != null && string.Equals(destination, containerPath, StringComparison.OrdinalIgnoreCase)))
                        throw new IOException("Bundled assembly collides with input/output: " + pair.Key);
                    if (File.Exists(destination) || Directory.Exists(destination))
                        throw new IOException("Bundled assembly output already exists: " + destination);
                    byte[] dependency = RestoreBundledAssembly(pair.Key, pair.Value, renameAll);
                    bundledOutputs.Add(destination, dependency);
                }
            Directory.CreateDirectory(directory);
            string temporary = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
            var staged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var committed = new List<string>();
            bool completed = false;
            try
            {
                if (exactBytes != null)
                {
                    using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write))
                        stream.Write(exactBytes, 0, exactBytes.Length);
                    if (Hash(File.ReadAllBytes(temporary)) != inputHash) throw new IOException("Plain input copy differs.");
                }
                else if (module.IsILOnly)
                {
                    var options = new ModuleWriterOptions(module);
                    options.MetadataOptions.Flags = GetWriterMetadataFlags(preserveMetadata);
                    module.Write(temporary, options);
                    Console.WriteLine("WRITER compact managed PE");
                }
                else
                {
                    var options = new NativeModuleWriterOptions(module, true);
                    options.KeepExtraPEData = true;
                    options.KeepWin32Resources = true;
                    options.MetadataOptions.Flags = GetWriterMetadataFlags(preserveMetadata);
                    module.NativeWrite(temporary, options);
                    Console.WriteLine("WRITER native sections preserved");
                }
                using (var check = ModuleDefMD.Load(temporary))
                    Console.WriteLine("OUTPUT methods=" + check.GetTypes().Sum(t => t.Methods.Count));
                foreach (var pair in bundledOutputs)
                {
                    string file = pair.Key + "." + Guid.NewGuid().ToString("N") + ".tmp";
                    using (var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write))
                    {
                        staged.Add(pair.Key, file);
                        stream.Write(pair.Value, 0, pair.Value.Length);
                    }
                    if (Hash(File.ReadAllBytes(file)) != Hash(pair.Value)) throw new IOException("Bundled assembly staging hash differs.");
                }
                if (Hash(File.ReadAllBytes(input)) != inputHash) throw new IOException("Input hash changed.");
                
                foreach (var pair in staged)
                {
                    File.Move(pair.Value, pair.Key);
                    committed.Add(pair.Key);
                }
                File.Move(temporary, output);
                completed = true;
                if (bundledOutputs.Count != 0) Console.WriteLine("BUNDLED saved=" + bundledOutputs.Count + " directory=" + directory);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
                foreach (var file in staged.Values) if (File.Exists(file)) File.Delete(file);
                if (!completed)
                    foreach (var file in committed)
                        if (File.Exists(file) && Hash(File.ReadAllBytes(file)) == Hash(bundledOutputs[file])) File.Delete(file);
            }
        }

        private static MetadataFlags GetWriterMetadataFlags(bool preserveMetadata)
        {

            return MetadataFlags.KeepOldMaxStack | (preserveMetadata
                ? MetadataFlags.PreserveAll & ~MetadataFlags.PreserveStandAloneSigRids
                : (MetadataFlags)0);
        }

        private static string Hash(byte[] bytes)
        {
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
        }
    }
}
