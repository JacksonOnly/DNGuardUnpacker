using System;
using System.Collections.Generic;
using System.Text;
using dnlib.PE;
using dnlib.IO;

namespace DNGuard_Unpacker
{
    internal sealed class NativePeInfo
    {
        internal string Architecture { get; private set; }
        internal uint ClrRva { get; private set; }
        internal List<string> Exports { get; } = new List<string>();
        internal bool IsVmRuntime => Exports.Contains("VMRuntime");

        internal static NativePeInfo Read(byte[] bytes)
        {
            using (var pe = new PEImage(bytes))
            {
                var machine = pe.ImageNTHeaders.FileHeader.Machine;
                var info = new NativePeInfo {
                    Architecture = machine == Machine.I386 ? "x86" : machine == Machine.AMD64 ? "x64" : machine.ToString(),
                    ClrRva = (uint)pe.ImageNTHeaders.OptionalHeader.DataDirectories[14].VirtualAddress
                };
                uint raw;
                uint exportRva = (uint)pe.ImageNTHeaders.OptionalHeader.DataDirectories[0].VirtualAddress;
                if (exportRva == 0 || !TryRaw(pe, bytes, exportRva, 40, out raw)) return info;
                uint count = BitConverter.ToUInt32(bytes, checked((int)raw + 24));
                uint namesRva = BitConverter.ToUInt32(bytes, checked((int)raw + 32));
                for (uint index = 0; index < Math.Min(count, 64U); index++)
                {
                    ulong entry = (ulong)namesRva + index * 4UL;
                    if (entry > uint.MaxValue || !TryRaw(pe, bytes, (uint)entry, 4, out raw)) break;
                    uint nameRva = BitConverter.ToUInt32(bytes, (int)raw);
                    if (!TryRaw(pe, bytes, nameRva, 1, out raw)) continue;
                    int start = checked((int)raw), end = start;
                    while (end < bytes.Length && end - start < 256 && bytes[end] != 0) end++;
                    if (end < bytes.Length && end - start < 256) info.Exports.Add(Encoding.ASCII.GetString(bytes, start, end - start));
                }
                return info;
            }
        }

        private static bool TryRaw(IPEImage pe, byte[] bytes, uint rva, uint size, out uint raw)
        {
            raw = (uint)pe.ToFileOffset((RVA)rva);
            return raw != 0 && (uint)pe.ToRVA((FileOffset)raw) == rva && (ulong)raw + size <= (ulong)bytes.Length;
        }
    }
}
