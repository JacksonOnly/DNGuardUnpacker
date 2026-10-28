using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text;

namespace DNGuard_Unpacker
{
    internal static class SourceExportLauncher
    {
        internal static string Resolve(string explicitPath)
        {
            if (explicitPath != null)
            {
                string full = Path.GetFullPath(explicitPath);
                if (!File.Exists(full)) throw new FileNotFoundException("SourceExporter not found.", full);
                return full;
            }
            string root = AppDomain.CurrentDomain.BaseDirectory;
            string path = new[] {
                Path.Combine(root, "source-exporter", "SourceExporter.exe"),
                Path.Combine(root, "SourceExporter.exe"),
                Path.Combine(root, "..", "..", "..", "..", "SourceExporter", "bin", "Release", "net10.0", "SourceExporter.exe")
            }.Select(Path.GetFullPath).FirstOrDefault(File.Exists);
            if (path == null) throw new FileNotFoundException("Build Lab/SourceExporter in Release, or supply --source-exporter PATH.");
            return path;
        }

        internal static void ValidateOutput(string directory)
        {
            if (Directory.Exists(directory) || File.Exists(directory)) throw new IOException("Source output already exists: " + directory);
        }

        internal static void Run(string executable, string input, string output, bool restoreAsync = false, bool pruneEmpty = false,
            IEnumerable<string> referenceDirectories = null, bool allowMissingReferences = false, bool renameAll = false)
        {
            ValidateOutput(output);
            Execute(executable, Quote(input) + " " + Quote(output) +
                (restoreAsync ? " --async" : "") + (pruneEmpty ? " --prune-empty" : "") +
                (renameAll ? " --rename-all" : "") + (allowMissingReferences ? " --allow-missing-references" : "") +
                string.Concat((referenceDirectories ?? Enumerable.Empty<string>()).Select(d => " --reference-dir " + Quote(d))) +
                (ConsoleLog.Verbose ? " --verbose" : "") + (ConsoleLog.Quiet ? " --quiet" : ""),
                "Source export failed; existing unpacked binary and diagnostic output are preserved.");
            Console.WriteLine("SOURCE " + output);
        }

        internal static void RecoverTypes(string executable, string input)
        {
            Execute(executable, "recover-types " + Quote(input) + (ConsoleLog.Verbose ? " --verbose" : ""),
                "Type recovery failed; inspect its diagnostics and backup before continuing.");
        }

        private static void Execute(string executable, string arguments, string failure)
        {
            var start = new ProcessStartInfo(executable, arguments) {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = new UTF8Encoding(false), StandardErrorEncoding = new UTF8Encoding(false),
                WorkingDirectory = Path.GetDirectoryName(executable)
            };
            if (ConsoleLog.Legacy) start.EnvironmentVariables["DNG_LOG_FORMAT"] = "legacy";
            using (var process = new Process { StartInfo = start })
            {
                process.OutputDataReceived += (sender, e) => { if (e.Data != null) Console.WriteLine(e.Data); };
                process.ErrorDataReceived += (sender, e) => { if (e.Data != null) Console.Error.WriteLine(e.Data); };
                process.Start();
                process.BeginOutputReadLine(); process.BeginErrorReadLine();
                process.WaitForExit();
                if (process.ExitCode != 0) throw new InvalidOperationException(failure);
            }
        }

        private static string Quote(string value)
        {
            var result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes);
                result.Append(c); slashes = 0;
            }
            result.Append('\\', slashes * 2);
            return result.Append('"').ToString();
        }
    }
}
