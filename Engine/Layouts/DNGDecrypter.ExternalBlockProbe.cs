using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.PE;
using DNGuard_Unpacker.Versions;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        private void RecoverExternalMethodsOrThrow(uint[] words)
        {
            byte[] file = this.module.Metadata.PEImage.CreateReader().ToArray();
            byte[] recovered = FindExternalMethodBlock(this.module, file);
            if (recovered != null)
            {
                this.externalMethods = recovered;
                this.recoveredModernBlock = true;
                return;
            }
            uint compressed = Profile.CompressedMethodsSize(words, Profile.Chained);
            ulong table = (ulong)this.DataStructure.MethodsCount * 4;
            uint leh = words[Profile.LehSizeIndex];
            var evidence = new LayoutExternalBlockEvidence
            {
                MethodsCount = this.DataStructure.MethodsCount,
                TableBytes = table,
                CompressedMethodsBytes = compressed,
                CompressedLehBytes = leh,
                ExpectedTotalBytes = table + compressed + leh,
                ExpandedMethodsBytes = this.UncompressedMethodsBufferLength,
                SearchScope = "current-module-file",
                HeaderAndKeyValidated = true,
                Available = false
            };
            for (int at = 0; at <= file.Length - 4; at++)
                if (BitConverter.ToUInt32(file, at) == this.UncompressedMethodsBufferLength)
                    evidence.ExpandedLengthMarkerOccurrences++;
            var error = new InvalidDataException("Application Mode method block is external. Unpack the original Single EXE, or supply --container ORIGINAL_EXE for this extracted module." +
                " 当前模块内未找到通过校验的完整方法块；方法记录=" + evidence.MethodsCount +
                "，所需外置字节=" + evidence.ExpectedTotalBytes + "。没有原始容器或完整数据块时，不能还原缺失的方法体。");
            error.Data["DNGuard.ExternalMethodBlock"] = evidence;
            throw error;
        }

        
        
        
        internal static byte[] FindExternalMethodBlock(ModuleDefMD module, byte[] container)
        {
            var source = new DNGDecrypter(module);
            byte[] header = null;
            foreach (int size in ModernVersionRegistry.Profiles.Select(p => p.HeaderSize).Distinct())
            {
                byte[] candidate = null;
                if ((ulong)source.DataOffset + (uint)size <= source.reader.Length && source.GetStructSize(size, ref candidate) == size) { header = candidate; break; }
            }
            if (header == null) return null;
            var encoded = new uint[header.Length / 4];
            Buffer.BlockCopy(header, 0, encoded, 0, header.Length);
            byte[] selected = null;
            var checkedCandidates = new HashSet<string>();
            foreach (var profile in ModernVersionRegistry.Profiles)
            {
                if (profile.HeaderSize != header.Length) continue;
                uint[] words = encoded;
                if (profile.Chained)
                {
                    if (encoded[1] != encoded[2]) continue;
                    uint key;
                    uint keyRva = encoded[profile.KeyIndex] ^ encoded[profile.KeyIndex - 1];
                    if (!source.TryKeyChecksum(keyRva, out key)) continue;
                    uint marker = encoded[0] ^ key;
                    if ((marker & 0xFFFF) != 124 || marker >> 16 > 127) continue;
                    words = new uint[31];
                    for (int i = 0; i < words.Length; i++) words[i] = encoded[i] ^ (i == 0 ? 0 : encoded[i - 1]) ^ key;
                }
                else if (encoded[0] != profile.Marker) continue;
                uint settings = profile.Settings(words);
                if ((settings & (uint)ProtectSettings.ApplicationMode) == 0 || (settings & 0xFFF00000) != 0 ||
                    !source.VerifyModernKeyAtRva(words[profile.KeyIndex] ^ words[2], words[2])) continue;
                uint count = words[profile.MethodsCountIndex], expanded = words[profile.ExpandedMethodsIndex], leh = words[profile.LehSizeIndex];
                if (count < 3 || count > module.TablesStream.MethodTable.Rows || expanded == 0 || expanded > 64 * 1024 * 1024) continue;
                foreach (uint compressed in new[] { profile.CompressedMethodsSize(words, false), profile.CompressedMethodsSize(words, true) }.Distinct())
                {
                    ulong tableLength = (ulong)count * 4;
                    ulong total = tableLength + compressed + leh;
                    if (compressed < 4 || total > (ulong)container.Length || total > 128 * 1024 * 1024) continue;
                    for (int at = checked((int)tableLength); (ulong)at + compressed + leh <= (ulong)container.Length; at++)
                    {
                        if (BitConverter.ToUInt32(container, at) != expanded) continue;
                        int start = checked(at - (int)tableLength);
                        if (!checkedCandidates.Add(start + ":" + total)) continue;
                        var block = new byte[(int)total];
                        Buffer.BlockCopy(container, start, block, 0, block.Length);
                        try
                        {
                            var probe = new DNGDecrypter(module, block);
                            probe.suppressLayoutLog = true;
                            probe.ParseStructure();
                            if (!probe.modernLayout) continue;
                            var table = new byte[(int)tableLength];
                            Buffer.BlockCopy(block, 0, table, 0, table.Length);
                            if (!probe.ValidateModernProbeTable(table)) continue;
                            var packed = new byte[compressed];
                            Buffer.BlockCopy(block, table.Length, packed, 0, packed.Length);
                            if (new LZAri().Decode(packed).Length != expanded) continue;
                            if (leh != 0)
                            {
                                var packedLeh = new byte[leh];
                                Buffer.BlockCopy(block, checked(table.Length + packed.Length), packedLeh, 0, packedLeh.Length);
                                byte[] decodedLeh = new LZAri().Decode(packedLeh);
                                if (decodedLeh.Length > 64 * 1024 * 1024) continue;
                            }
                        }
                        catch (InvalidDataException) { continue; }
                        catch (NotSupportedException) { continue; }
                        catch (ArgumentException) { continue; }
                        catch (IOException) { continue; }
                        catch (OverflowException) { continue; }
                        catch (IndexOutOfRangeException) { continue; }
                        if (selected != null && !selected.SequenceEqual(block))
                            throw new InvalidDataException("自动搜索发现多个有效外部方法块，拒绝不明确的候选。");
                        selected = block;
                    }
                }
            }
            if (selected != null) Console.WriteLine("PROBE 已通过数据头、描述符及压缩流校验定位外部方法块；bytes=" + selected.Length);
            return selected;
        }
    }
}
