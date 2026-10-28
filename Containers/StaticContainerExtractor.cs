using System;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.PE;
using dnlib.IO;
using dnlib.W32Resources;

namespace DNGuard_Unpacker
{
    
    public static class StaticContainerExtractor
    {
        public sealed class Result
        {
            public byte[] Module { get; internal set; }
            public byte[] Methods { get; internal set; }
            public string Machine { get; internal set; }
            public int HeaderOffset { get; internal set; }
            public uint HeaderSize { get; internal set; }
            public Win32ResourcesUser PresentationResources { get; internal set; }

            public IReadOnlyDictionary<string, byte[]> BundledAssemblies { get; internal set; }

            public string BundledApplicationName { get; internal set; }

            public void ApplyPresentationResources(ModuleDef module)
            {
                if (PresentationResources == null || PresentationResources.Root.Directories.Count == 0) return;
                var root = module.Win32Resources == null || module.Win32Resources.Root == null
                    ? new ResourceDirectoryUser(0) : CloneDirectory(module.Win32Resources.Root);
                foreach (var directory in PresentationResources.Root.Directories)
                {
                    var old = root.FindDirectory(directory.Name);
                    if (old != null) root.Directories.Remove(old);
                    root.Directories.Add(CloneDirectory(directory));
                }
                module.Win32Resources = new Win32ResourcesUser { Root = root };
                Console.WriteLine("SYNC Win32 resource types=" + string.Join(",", PresentationResources.Root.Directories.Select(d => d.Name.ToString())));
            }
        }

        public static Result Extract(byte[] input, string sourcePath = null)
        {
            Result result = null;
            using (var pe = new PEImage(input))
            {
                var machine = pe.ImageNTHeaders.FileHeader.Machine;
                if (machine != Machine.I386 && machine != Machine.AMD64)
                    throw new NotSupportedException("Unsupported Single EXE machine: " + machine);
                
                
                
                if (pe.Win32Resources != null && pe.Win32Resources.Root != null)
                    result = ExtractResourceBundle(pe.Win32Resources.Root, input, pe);
                foreach (var section in pe.ImageSectionHeaders)
                {
                    long start = section.PointerToRawData;
                    long end = start + section.SizeOfRawData;
                    if (start < 0 || end > input.Length) throw new InvalidDataException("Container section outside input.");
                    for (long at = start; at <= end - 56; at++)
                    {
                        int offset = checked((int)at);
                        if (result != null && offset == result.HeaderOffset) continue;
                        uint marker = BitConverter.ToUInt32(input, offset) & 0xFFFFFF;

                        uint headerSize = BitConverter.ToUInt32(input, offset + 4);
                        if (!IsSupportedMarker(marker) || !IsSupportedHeaderSize(headerSize)) continue;
                        Result candidate;
                        try { candidate = ReadCandidate(input, offset, end); }
                        catch (InvalidDataException) { continue; }
                        catch (NotSupportedException) { continue; }
                        catch (ArgumentException) { continue; }
                        catch (IOException) { continue; }
                        catch (OverflowException) { continue; }
                        catch (IndexOutOfRangeException) { continue; }
                        if (candidate == null) continue;
                        if (result != null) throw new InvalidDataException("Multiple validated Single EXE payloads; refusing an ambiguous selection.");
                        candidate.Machine = machine == Machine.AMD64 ? "AMD64" : "I386";
                        result = candidate;
                    }
                }
                if (result == null)
                    result = TryExtractHuffmanManagedModule(input, pe, machine);
                if (result != null)
                {
                    result.Machine = machine == Machine.AMD64 ? "AMD64" : "I386";
                    var root = new ResourceDirectoryUser(0);
                    if (pe.Win32Resources != null && pe.Win32Resources.Root != null)
                        foreach (var directory in pe.Win32Resources.Root.Directories)
                            if (directory.Name.HasId && IsPresentationType(directory.Name.Id)) root.Directories.Add(CloneDirectory(directory));
                    result.PresentationResources = new Win32ResourcesUser { Root = root };
                }
            }
            if (result == null) throw new NotSupportedException("No supported static Single EXE payload found. Input was not executed.");
            return result;
        }

        private static Result ExtractResourceBundle(ResourceDirectory directory, byte[] input, PEImage pe)
        {
            Result result = null;
            foreach (var data in directory.Data)
            {
                var reader = data.CreateReader();
                if (reader.Length < 24) continue;
                byte[] bytes = reader.ToArray();
                uint marker = BitConverter.ToUInt32(bytes, 0) & 0xFFFFFF;
                if (marker != 0x520010 && !IsSupportedMarker(marker))
                {
                    if (marker < 0x480010 && (marker & 0xFFFF) == 0x10 && IsSupportedHeaderSize(BitConverter.ToUInt32(bytes, 4)))
                        throw new NotSupportedException("Unrecognized structured Single EXE resource marker; refusing partial payload carving.");
                    continue;
                }
                if (!IsSupportedHeaderSize(BitConverter.ToUInt32(bytes, 4)))
                {
                    if (marker == 0x520010 || bytes[3] == 1) throw new InvalidDataException("Invalid structured Single EXE resource header.");
                    continue;
                }
                int headerOffset = checked((int)reader.StartOffset);
                Result candidate;
                if (marker == 0x520010) candidate = ReadCandidate(bytes, 0, bytes.Length, true);
                else
                {
                    
                    
                    var owner = pe.ImageSectionHeaders.SingleOrDefault(s => headerOffset >= s.PointerToRawData &&
                        (ulong)headerOffset < (ulong)s.PointerToRawData + s.SizeOfRawData);
                    if (owner == null) throw new InvalidDataException("Single EXE resource has no containing section.");
                    long end = (long)owner.PointerToRawData + owner.SizeOfRawData;
                    if (end > input.Length) throw new InvalidDataException("Single EXE resource section is truncated.");
                    
                    
                    
                    try { candidate = ReadCandidate(input, headerOffset, end); }
                    catch (Exception error) when (bytes[3] != 1 &&
                        (error is IOException || error is NotSupportedException || error is ArgumentException || error is OverflowException))
                    { continue; }
                }
                if (candidate == null)
                {
                    if (marker == 0x520010 || bytes[3] == 1) throw new InvalidDataException("Invalid structured Single EXE resource payload.");
                    continue;
                }
                candidate.HeaderOffset = headerOffset;
                if (result != null) throw new InvalidDataException("Multiple mixed Single EXE resource payloads.");
                result = candidate;
            }
            foreach (var child in directory.Directories)
            {
                var candidate = ExtractResourceBundle(child, input, pe);
                if (candidate == null) continue;
                if (result != null) throw new InvalidDataException("Multiple mixed Single EXE resource payloads.");
                result = candidate;
            }
            return result;
        }

        private static bool IsPresentationType(int type)
        {
            return type == 1 || type == 3 || type == 12 || type == 14 || type == 16 || type == 21 || type == 22 || type == 24;
        }

        private static bool IsSupportedMarker(uint marker)
        {

            return marker == 0x480010 || marker == 0x490010 || marker == 0x590010 || marker == 0x690010 || marker == 0x790010 ||
                marker == 0x890010 || marker == 0x990010 || marker == 0xA90010 || marker == 0xB90010 ||
                marker == 0xC20010 || marker == 0xE20010;
        }

        private static bool IsSupportedHeaderSize(uint size)
        {

            return size == 24 || size == 40 || (size >= 32 && size <= 24 + 256 * 8 && (size - 24) % 8 == 0);
        }

        private static bool IsManagedLengthVector(byte[] input, int offset, long sectionEnd)
        {

            ulong tail = (ulong)offset + BitConverter.ToUInt32(input, offset + 12) + BitConverter.ToUInt32(input, offset + 16);
            for (int field = 24; field < 40; field += 8)
            {
                ulong length = BitConverter.ToUInt64(input, offset + field);
                if (length == 0) continue;
                if (length < 10 || length > int.MaxValue || tail > (ulong)sectionEnd || length > (ulong)sectionEnd - tail) return false;
                var packed = new byte[(int)length];
                Buffer.BlockCopy(input, checked((int)tail), packed, 0, packed.Length);
                ValidateHuffmanHeader(packed);
                byte[] decoded = Compressor.Decompress(packed);
                if (!ContainerExtractor.IsManaged(decoded)) return false;
                using (var assembly = ModuleDefMD.Load(decoded)) return assembly.Assembly != null;
            }
            return false;
        }
        private static bool HasLegacyHeaderMarker(ModuleDefMD module)
        {
            try
            {
                for (int size = 4; size <= 396; size += 4)
                {
                    byte[] header = null;
                    var probe = new DNGDecrypter(module);
                    if (probe.GetStructSize(size, ref header) != size || header == null || header.Length < 4) continue;
                    return true;
                }
            }
            catch (BadImageFormatException) { }
            catch (InvalidDataException) { }
            catch (ArgumentException) { }
            catch (Exception) { }
            return false;
        }
        private static Result TryExtractHuffmanManagedModule(byte[] input, PEImage pe, Machine machine)
        {
            Result result = null;
            foreach (var section in pe.ImageSectionHeaders)
            {
                long start = section.PointerToRawData;
                long end = start + section.SizeOfRawData;
                if (start < 0 || end > input.Length) continue;
                for (long at = start; at <= end - 5; at++)
                {
                    int offset = checked((int)at);
                    int tableBytes = 0;
                    bool lzw = IsPackedLzwPe(input, offset, end);
                    if (!lzw && !TryReadHuffmanHeader(input, offset, end, out tableBytes)) continue;
                    if (lzw) tableBytes = 5;
                    var packed = new byte[checked((int)(end - at))];
                    Buffer.BlockCopy(input, offset, packed, 0, packed.Length);
                    byte[] moduleBytes;
                    try { moduleBytes = lzw ? FixedWidthLzw.Decode(packed) : Compressor.Decompress(packed); }
                    catch (Exception) { continue; }
                    if (moduleBytes.Length < 512) continue;
                    try { if (!ContainerExtractor.IsManaged(moduleBytes)) continue; }
                    catch (BadImageFormatException) { continue; }
                    catch (IOException) { continue; }
                    catch (ArgumentException) { continue; }
                    ModuleDefMD module;
                    try { module = ModuleDefMD.Load(moduleBytes); }
                    catch (BadImageFormatException) { continue; }
                    catch (IOException) { continue; }
                    catch (ArgumentException) { continue; }
                    byte[] external = null;
                    using (module)
                    {
                        if (module.EntryPoint == null || !module.GetTypes().Any(t => t.Name == "ZYXDNGuarder")) continue;
                        if (!HasLegacyHeaderMarker(module)) continue;
                        external = DNGDecrypter.FindExternalMethodBlock(module, input);
                    }
                    if (result != null)
                        throw new InvalidDataException("Multiple Huffman-packed managed payloads; refusing an ambiguous selection.");
                    result = new Result
                    {
                        Module = moduleBytes,
                        Methods = external,
                        Machine = machine == Machine.AMD64 ? "AMD64" : "I386",
                        HeaderOffset = offset,
                        HeaderSize = (uint)tableBytes,
                        BundledAssemblies = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
                    };
                }
            }
            return result;
        }

        private static bool IsPackedLzwPe(byte[] input, int offset, long end)
        {
            if ((long)offset + 9 > end) return false;
            uint size = BitConverter.ToUInt32(input, offset);
            int width = input[offset + 4];
            if (size < 512 || size > 64 * 1024 * 1024 || width < 9 || width > 16) return false;
            uint codes = BitConverter.ToUInt32(input, offset + 5);
            uint mask = (1U << width) - 1;
            return (codes & mask) == 0x4D && ((codes >> width) & mask) == 0x5A;
        }
        private static bool TryReadHuffmanHeader(byte[] input, int offset, long sectionEnd, out int tableBytes)
        {
            tableBytes = 0;
            if (offset < 0 || (long)offset + 5 > sectionEnd) return false;
            uint size = BitConverter.ToUInt32(input, offset);
            if (size < 512 || size > 64 * 1024 * 1024) return false;
            int symbols = input[offset + 4] + 1;
            
            
            if (symbols < 3) return false;
            int bytes = 5 + symbols * 5;
            if ((long)offset + bytes > sectionEnd) return false;
            bool[] seen = new bool[256];
            uint previous = uint.MaxValue;
            ulong total = 0;
            for (int i = 0; i < symbols; i++)
            {
                int entry = offset + 5 + i * 5;
                uint frequency = BitConverter.ToUInt32(input, entry);
                byte symbol = input[entry + 4];
                if (frequency == 0 || frequency > previous || seen[symbol]) return false;
                previous = frequency;
                seen[symbol] = true;
                total += frequency;
            }
            if (total != size || !seen[0] || !seen[0x4D] || !seen[0x5A]) return false;
            tableBytes = bytes;
            return true;
        }

                private static ResourceDirectoryUser CloneDirectory(ResourceDirectory source)
        {
            var copy = new ResourceDirectoryUser(source.Name)
            {
                Characteristics = source.Characteristics, TimeDateStamp = source.TimeDateStamp,
                MajorVersion = source.MajorVersion, MinorVersion = source.MinorVersion
            };
            foreach (var child in source.Directories) copy.Directories.Add(CloneDirectory(child));
            foreach (var data in source.Data)
            {
                byte[] bytes = data.CreateReader().ToArray();
                copy.Data.Add(new ResourceData(data.Name, ByteArrayDataReaderFactory.Create(bytes, null), 0, (uint)bytes.Length, data.CodePage, data.Reserved));
            }
            return copy;
        }

        private static Result ReadCandidate(byte[] input, int offset, long sectionEnd, bool mixedFiles = false)
        {
            uint first = BitConverter.ToUInt32(input, offset + 8);
            uint second = BitConverter.ToUInt32(input, offset + 12);
            uint secondSize = BitConverter.ToUInt32(input, offset + 16);
            uint firstSize = BitConverter.ToUInt32(input, offset + 20);
            uint headerSize = BitConverter.ToUInt32(input, offset + 4);
            if ((long)offset + headerSize + 4 > sectionEnd) return null;
            uint entryCount = BitConverter.ToUInt32(input, checked(offset + (int)headerSize));
            if (first < Math.Max(56U, headerSize + 8U) || first > 4096 || (firstSize != 0 && firstSize < 16) || secondSize < 10 ||
                (ulong)first + firstSize != second || (long)offset + second + secondSize > sectionEnd ||
                entryCount > 256 || (headerSize != 24 && entryCount == 0)) return null;

            var packed = new byte[checked((int)secondSize)];
            Buffer.BlockCopy(input, checked(offset + (int)second), packed, 0, packed.Length);
            ValidateHuffmanHeader(packed);
            byte[] moduleBytes = mixedFiles ? Compressor.DecompressEntry(packed) : Compressor.Decompress(packed);
            byte[] methods = firstSize == 0 ? null : new byte[checked((int)firstSize)];
            if (methods != null) Buffer.BlockCopy(input, checked(offset + (int)first), methods, 0, methods.Length);
            string applicationName;
            using (var module = ModuleDefMD.Load(moduleBytes))
            {
                if (module.EntryPoint == null || !module.GetTypes().Any(t => t.Name == "ZYXDNGuarder")) return null;
                new DNGDecrypter(module, methods).ParseStructure();
                applicationName = Path.GetFileNameWithoutExtension(module.Name.String);
            }

            ulong tail = (ulong)offset + second + secondSize;
            var bundled = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            bool lengthVector = headerSize != 24 && (headerSize != 40 || IsManagedLengthVector(input, offset, sectionEnd));
            if (headerSize == 40 && !lengthVector)
            {
                for (int field = 24; field < 40; field += 4)
                {
                    uint length = BitConverter.ToUInt32(input, offset + field);
                    if (length == 0) continue;
                    if (length < 10 || tail + length > (ulong)sectionEnd) return null;
                    var runtime = new byte[checked((int)length)];
                    Buffer.BlockCopy(input, checked((int)tail), runtime, 0, runtime.Length);
                    ValidateHuffmanHeader(runtime);
                    tail += length;
                }
            }
            else if (lengthVector)
            {
                ulong totalDecoded = 0;
                for (int field = 24; field < headerSize; field += 8)
                {
                    ulong length = BitConverter.ToUInt64(input, checked(offset + field));
                    if (length == 0) continue;
                    
                    if (length < 10 || length > int.MaxValue || tail > (ulong)sectionEnd || length > (ulong)sectionEnd - tail) return null;
                    var dependency = new byte[(int)length];
                    Buffer.BlockCopy(input, checked((int)tail), dependency, 0, dependency.Length);
                    ValidateHuffmanHeader(dependency);
                    totalDecoded += BitConverter.ToUInt32(dependency, 0);
                    if (totalDecoded > 256UL * 1024 * 1024) return null;
                    byte[] decoded = mixedFiles ? Compressor.DecompressEntry(dependency) : Compressor.Decompress(dependency);
                    if (mixedFiles)
                    {
                        string name = BundledFileNames.Read(decoded, applicationName);
                        if (bundled.ContainsKey(name)) throw new InvalidDataException("Duplicate bundled file name: " + name);
                        bundled.Add(name, decoded);
                    }
                    else using (var assembly = ModuleDefMD.Load(decoded))
                    {
                        string name = assembly.Name.String;
                        if (assembly.Assembly == null || string.IsNullOrEmpty(name) || name != Path.GetFileName(name) ||
                            name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                            (!name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) ||
                            bundled.ContainsKey(name)) return null;
                        bundled.Add(name, decoded);
                    }
                    tail += length;
                }
                if (bundled.Count == 0) return null;
            }
            if (mixedFiles && tail != (ulong)sectionEnd) throw new InvalidDataException("Mixed Single EXE vector does not consume the complete resource.");
            return new Result { Module = moduleBytes, Methods = methods, HeaderOffset = offset, HeaderSize = headerSize,
                BundledAssemblies = bundled, BundledApplicationName = mixedFiles ? applicationName : null };
        }

        private static void ValidateHuffmanHeader(byte[] packed)
        {
            uint size = BitConverter.ToUInt32(packed, 0);
            int count = packed[4] + 1;
            if (size < 512 || size > 64 * 1024 * 1024 || 5 + count * 5 > packed.Length)
                throw new InvalidDataException("Invalid Single EXE compressed module header.");
            var seen = new bool[256];
            ulong total = 0;
            uint previous = uint.MaxValue;
            for (int i = 0; i < count; i++)
            {
                uint frequency = BitConverter.ToUInt32(packed, 5 + i * 5);
                byte symbol = packed[9 + i * 5];
                if (frequency == 0 || frequency > previous || seen[symbol])
                    throw new InvalidDataException("Invalid Single EXE Huffman frequency table.");
                previous = frequency;
                seen[symbol] = true;
                total += frequency;
            }
            if (total != size) throw new InvalidDataException("Single EXE Huffman frequency sum mismatch.");
        }
    }
}
