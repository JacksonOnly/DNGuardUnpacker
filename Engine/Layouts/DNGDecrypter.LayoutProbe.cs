using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.IO;
using dnlib.PE;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        
        public static LayoutProbeReport ProbeLayout(ModuleDefMD module, byte[] externalMethods = null)
        {
            var probe = new DNGDecrypter(module, externalMethods);
            var report = new LayoutProbeReport();
            byte[] header = null;
            for (int size = 4; size <= 396; size += 4)
            {
                byte[] candidate = null;
                if ((ulong)probe.DataOffset + (uint)size > probe.reader.Length || probe.GetStructSize(size, ref candidate) == 0) continue;
                if (header != null) throw new InvalidDataException("数据头长度存在歧义。");
                header = candidate;
            }
            if (header == null) { report.Diagnostic = "未找到通过校验和的数据头。"; return report; }
            report.HeaderSize = header.Length;
            report.Marker = BitConverter.ToUInt32(header, 0);
            try { probe.ParseStructure(); report.Recognized = true; report.Layout = probe.LayoutName; }
            catch (NotSupportedException error) { report.Diagnostic = error.Message; }
            catch (InvalidDataException error)
            {
                report.Diagnostic = error.Message;
                report.ExternalMethods = error.Data["DNGuard.ExternalMethodBlock"] as LayoutExternalBlockEvidence;
            }
            var words = new uint[header.Length / 4];
            Buffer.BlockCopy(header, 0, words, 0, header.Length);
            for (int keyIndex = 0; keyIndex < words.Length; keyIndex++)
            {
                for (int encIndex = 0; encIndex < words.Length; encIndex++)
                {
                    if (words[encIndex] == 0) continue;
                    uint rva = words[keyIndex] ^ words[encIndex];
                    if (probe.VerifyModernKeyAtRva(rva, words[encIndex]))
                        report.Keys.Add(new LayoutKeyEvidence { KeyIndex = keyIndex, EncryptionIndex = encIndex, KeyRva = rva, EncryptionDword = words[encIndex] });
                }
                if (keyIndex > 0 && words.Length == 31 && words[1] == words[2])
                {
                    uint rva = words[keyIndex] ^ words[keyIndex - 1];
                    uint checksum;
                    if (probe.TryKeyChecksum(rva, out checksum) && ((words[0] ^ checksum) & 0xFFFF) == header.Length && (words[0] ^ checksum) >> 16 <= 127)
                        report.Keys.Add(new LayoutKeyEvidence { KeyIndex = keyIndex, EncryptionIndex = 2, KeyRva = rva, EncryptionDword = checksum, Chained = true });
                }
            }
            
            
            foreach (var key in report.Keys.Where(k => !k.Chained).Take(8))
                probe.ProbeMethodTables(words, key, report);
            if (report.Recognized && report.Blocks.Count == 0)
                report.Blocks.Add(new LayoutBlockEvidence { MethodsRva = probe.externalMethods == null ? probe.DataStructure.MethodsDataOffset : 0,
                    MethodsCount = probe.DataStructure.MethodsCount, ExpandedSize = probe.UncompressedMethodsBufferLength,
                    TableXorLength = probe.IsModernLayout ? 9 : -1 });
            return report;
        }

        private bool TryKeyChecksum(uint rva, out uint checksum)
        {
            checksum = 0;
            uint raw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva);
            if (raw == 0 || (ulong)raw + 20 > this.reader.Length || (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)raw) != rva) return false;
            this.reader.Position = raw;
            byte[] key = this.reader.ReadBytes(20);
            var adler = new Adler32(); adler.Update(key);
            long low = adler.Value & 65535, high = adler.Value >> 16;
            using (var md5 = MD5.Create())
                foreach (byte value in md5.ComputeHash(key)) { low += value; high += low; }
            checksum = (uint)((((high & 65535) + 15) << 16) | low);
            return true;
        }

        private void ProbeMethodTables(uint[] words, LayoutKeyEvidence key, LayoutProbeReport report)
        {
            this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)key.KeyRva);
            byte[] keyBytes = this.reader.ReadBytes(16);
            var counts = words.Select((v, i) => new { v, i }).Where(x => x.v >= 3 && x.v <= this.module.Metadata.TablesStream.MethodTable.Rows).GroupBy(x => x.v).Select(g => g.First()).ToArray();
            var sizes = words.Select((v, i) => new { v, i }).Where(x => x.v >= 32 && x.v <= 64 * 1024 * 1024).GroupBy(x => x.v).ToDictionary(g => g.Key, g => g.First().i);
            var seen = new HashSet<string>();
            foreach (var section in this.module.Metadata.PEImage.ImageSectionHeaders)
            {
                uint end = checked(section.PointerToRawData + section.SizeOfRawData);
                if (end > this.reader.Length) continue;
                
                for (uint at = section.PointerToRawData; (ulong)at + 4 <= end; at++)
                {
                    this.reader.Position = at;
                    uint expanded = this.reader.ReadUInt32();
                    int expandedIndex;
                    if (!sizes.TryGetValue(expanded, out expandedIndex)) continue;
                    foreach (var count in counts)
                    {
                        ulong tableBytes = (ulong)count.v * 4;
                        if (tableBytes > at - section.PointerToRawData || tableBytes > 4 * 1024 * 1024) continue;
                        uint start = checked(at - (uint)tableBytes);
                        this.reader.Position = start;
                        byte[] table = this.reader.ReadBytes((int)tableBytes);
                        DecryptPrevXor(table, keyBytes);
                        foreach (int length in new[] { 0, 9, 10, 20, table.Length }.Distinct())
                        {
                            if (length > table.Length) continue;
                            var decoded = (byte[])table.Clone();
                            if (length != 0) XorSelf(decoded, 0, length);
                            uint descriptors = 0; bool valid = true;
                            for (uint rid = 0; rid < count.v; rid++)
                            {
                                uint item = BitConverter.ToUInt32(decoded, (int)rid * 4);
                                uint kind = item >> 28;
                                if (item == 0 || (item >> 24) == 0xF8 || kind == 2 || kind == 4 || kind == 6 || kind == 12) continue;
                                uint rva = (item ^ key.EncryptionDword) & 0xFFFFFF;
                                uint raw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva);
                                if (raw == 0 || (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)raw) != rva || (ulong)raw + 6 > this.reader.Length) { valid = false; break; }
                                this.reader.Position = raw;
                                uint descriptor = this.reader.ReadUInt32();
                                uint cipher = descriptor & 255;
                                ulong offset;
                                if (cipher == 0xFE)
                                {
                                    cipher = (descriptor >> 8) & 255;
                                    this.reader.Position = raw + 2;
                                    offset = this.reader.ReadUInt32();
                                }
                                else offset = (ulong)(descriptor >> 8) * 8;
                                if ((cipher & 127) > 15 || offset >= expanded) { valid = false; break; }
                                descriptors++;
                            }
                            string identity = start + ":" + count.v + ":" + expanded + ":" + length;
                            if (!valid || descriptors < 3 || !seen.Add(identity)) continue;
                            report.Blocks.Add(new LayoutBlockEvidence { CountIndex = count.i, MethodsCount = count.v,
                                ExpandedIndex = expandedIndex, ExpandedSize = expanded, TableXorLength = length,
                                MethodsRva = (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)start), DescriptorCount = descriptors });
                            if (report.Blocks.Count >= 64) { report.Diagnostic = "已达到 64 个候选上限；拒绝无界搜索。"; return; }
                        }
                    }
                }
            }
        }
    }
}
