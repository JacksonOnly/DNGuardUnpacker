using System;
using System.IO;
using System.Linq;

namespace DNGuard_Unpacker
{
    
    public static class CompanionContainer
    {
        public static StaticContainerExtractor.Result Find(string inputPath, byte[] moduleBytes, out string containerPath)
        {
            containerPath = null;
            if (!string.Equals(Path.GetExtension(inputPath), ".dll", StringComparison.OrdinalIgnoreCase)) return null;
            string candidate = Path.ChangeExtension(Path.GetFullPath(inputPath), ".exe");
            if (!File.Exists(candidate)) return null;
            byte[] bytes = File.ReadAllBytes(candidate);
            StaticContainerExtractor.Result result;
            try
            {
                if (ContainerExtractor.IsManaged(bytes)) return null;
                result = StaticContainerExtractor.Extract(bytes, candidate);
            }
            catch (NotSupportedException) { return null; }
            catch (InvalidDataException) { return null; }
            catch (dnlib.IO.DataReaderException) { return null; }
            catch (BadImageFormatException) { return null; }
            catch (ArgumentException) { return null; }
            catch (OverflowException) { return null; }
            if (result.Methods == null || !moduleBytes.SequenceEqual(result.Module)) return null;
            if (!bytes.SequenceEqual(File.ReadAllBytes(candidate))) throw new IOException("配套容器在匹配期间发生变化。");
            containerPath = candidate;
            return result;
        }
    }
}
