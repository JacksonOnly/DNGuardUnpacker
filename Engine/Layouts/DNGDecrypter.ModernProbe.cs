using System;
using System.IO;
using System.Linq;
using dnlib.IO;
using dnlib.PE;
using DNGuard_Unpacker.Versions;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        private bool TryAutoChainedHeader(uint[] encoded, out ModernVersionProfile selected, out uint[] decoded)
        {
            selected = null; decoded = null;
            if (encoded.Length != 31 || encoded[1] != encoded[2]) return false;
            foreach (var candidate in ModernVersionRegistry.Profiles.Where(p => p.Chained))
            {
                uint rva = encoded[candidate.KeyIndex] ^ encoded[candidate.KeyIndex - 1];
                uint key;
                if (!TryKeyChecksum(rva, out key)) continue;
                uint marker = encoded[0] ^ key;
                if ((marker & 0xFFFF) != 124 || (marker >> 16) > 127) continue;
                var words = new uint[31];
                for (int i = 0; i < words.Length; i++) words[i] = encoded[i] ^ (i == 0 ? 0 : encoded[i - 1]) ^ key;
                uint settings = candidate.Settings(words);
                if ((settings & 0xFFFF0000) != 0 || words[candidate.MethodsCountIndex] == 0 ||
                    words[candidate.MethodsCountIndex] > this.module.Metadata.TablesStream.MethodTable.Rows ||
                    words[candidate.ExpandedMethodsIndex] == 0 || words[candidate.ExpandedMethodsIndex] > 64 * 1024 * 1024) continue;
                var probe = new DNGDecrypter(this.module, this.externalMethods);
                probe.DataStructure.MethodsCount = words[candidate.MethodsCountIndex];
                probe.UncompressedMethodsBufferLength = words[candidate.ExpandedMethodsIndex];
                bool valid = this.externalMethods != null ? probe.IsExternalBlockLayout(words[candidate.CompressedMethodsIndex], words[candidate.LehSizeIndex]) :
                    probe.IsModernBlockLayout(candidate.FirstMethodsRva(words, settings), words[candidate.CompressedMethodsIndex], words[candidate.LehSizeIndex]);
                if (!valid) continue;
                if (selected != null) throw new InvalidDataException("自动解链得到多个有效格式，拒绝不明确的候选。");
                selected = candidate; decoded = words;
            }
            if (selected != null) Console.WriteLine("PROBE 已通过密钥校验自动还原链式头；复用格式 " + selected.GetType().Name);
            return selected != null;
        }

        private uint FindModernMethodBlock(uint compressed, uint leh, bool validateStreams = false)
        {
            uint selected = 0;
            foreach (var section in this.module.Metadata.PEImage.ImageSectionHeaders)
            {
                ulong tableBytes = (ulong)this.DataStructure.MethodsCount * 4;
                ulong start = section.PointerToRawData + tableBytes;
                ulong end = (ulong)section.PointerToRawData + section.SizeOfRawData;
                if (end > this.reader.Length) continue;
                for (ulong at = start; at + compressed + leh <= end && at + 4 <= end; at++)
                {
                    this.reader.Position = (uint)at;
                    if (this.reader.ReadUInt32() != this.UncompressedMethodsBufferLength) continue;
                    uint raw = checked((uint)(at - tableBytes));
                    uint rva = (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)raw);
                    if (!IsModernBlockLayout(rva, compressed, leh)) continue;
                    if (validateStreams)
                    {
                        try
                        {
                            this.reader.Position = checked((uint)at);
                            modernTableProbeMethods = new LZAri().Decode(this.reader.ReadBytes(checked((int)compressed)));
                            if (modernTableProbeMethods.Length != this.UncompressedMethodsBufferLength) continue;
                            if (leh != 0)
                            {
                                byte[] packedLeh = this.reader.ReadBytes(checked((int)leh));
                                uint length = BitConverter.ToUInt32(packedLeh, 0);
                                if (length > 64 * 1024 * 1024) continue;
                                modernTableProbeLeh = new LZAri().Decode(packedLeh);
                                if (modernTableProbeLeh.Length != length) continue;
                                DecryptPrevXor(modernTableProbeLeh, this.KeyBuff);
                            }
                            else modernTableProbeLeh = new byte[0];
                            if (!ValidateModernProbeTable(raw)) continue;
                        }
                        catch (IOException) { continue; }
                        catch (ArgumentException) { continue; }
                        catch (OverflowException) { continue; }
                        catch (IndexOutOfRangeException) { continue; }
                        finally { modernTableProbeMethods = null; modernTableProbeLeh = null; }
                    }
                    else if (!ValidateModernProbeTable(raw)) continue;
                    if (selected != 0 && selected != rva) throw new InvalidDataException("自动搜索发现多个有效方法块。");
                    selected = rva;
                }
            }
            if (selected != 0) Console.WriteLine("PROBE 已自动定位方法块 RVA=0x" + selected.ToString("X8"));
            return selected;
        }

        private bool ValidateModernProbeTable(uint raw)
        {
            this.reader.Position = raw;
            byte[] table = this.reader.ReadBytes(checked((int)this.DataStructure.MethodsCount * 4));
            return ValidateModernProbeTable(table);
        }

        private bool ValidateModernProbeTable(byte[] table)
        {
            DecodeModernMethodTable(table);
            return ValidateDecodedModernProbeTable(table);
        }

        private bool ValidateDecodedModernProbeTable(byte[] decoded)
        {
            byte[] table = (byte[])decoded.Clone();
            if (table.Length < 9) return false;
            XorSelf(table, 0, 9);
            int descriptors = 0;
            for (uint rid = 1; rid <= this.DataStructure.MethodsCount; rid++)
            {
                uint item = BitConverter.ToUInt32(table, (int)(rid - 1) * 4);
                if (item == 0 || item >> 24 == 0xF8) continue;
                uint kind = (item >> 28) & Profile.KindMask;
                if (kind == 6) continue;
                if (kind != 0 && kind != 1 && kind != 2 && kind != 4 && kind != 5) return false;
                try
                {
                    byte cipher;
                    int offset = ReadModernDescriptor(item, rid, out cipher);
                    if ((cipher & 127) > 15 || offset < 0 || (ulong)offset + 8 > this.UncompressedMethodsBufferLength) return false;
                }
                catch (InvalidDataException) { return false; }
                catch (OverflowException) { return false; }
                descriptors++;
            }
            return descriptors != 0 && ValidateProbeRecordHeaders(table);
        }

        private bool ValidateProbeRecordHeaders(byte[] table)
        {
            if (modernTableProbeMethods == null) return true;
            try
            {
                for (uint rid = 1; rid <= this.DataStructure.MethodsCount; rid++)
                {
                    uint item = BitConverter.ToUInt32(table, checked((int)(rid - 1) * 4));
                    uint kind = (item >> 28) & Profile.KindMask;
                    if (item == 0 || item >> 24 == 0xF8 || kind == 6) continue;
                    byte cipher;
                    int at = ReadModernRecordOffset(modernTableProbeMethods, item, rid, out cipher);
                    RequireModernRange(modernTableProbeMethods, at, 8, rid, "probe record header");
                    uint header = BitConverter.ToUInt32(modernTableProbeMethods, at);
                    if ((header & 15) == 0 && this.module.ResolveMethod(rid).DeclaringType.FullName.Contains("ZYXDNGuarder")) continue;
                    uint length;
                    if ((header & 8) != 0) length = header >> 8;
                    else
                    {
                        int offset = checked((int)(header >> 8));
                        RequireModernRange(modernTableProbeLeh, offset, 12, rid, "probe LEH header");
                        length = BitConverter.ToUInt32(modernTableProbeLeh, offset + Profile.MethodLengthOffset(this.modernLehLengthFirst)) >> 8;
                    }
                    RequireModernRange(modernTableProbeMethods, (long)at + 8, ((long)length + 7) & ~7L, rid, "probe method payload");
                }
                return true;
            }
            catch (InvalidDataException) { return false; }
            catch (OverflowException) { return false; }
        }
    }
}
