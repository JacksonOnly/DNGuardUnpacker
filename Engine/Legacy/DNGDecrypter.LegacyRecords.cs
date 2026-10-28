using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.PE;
using dnlib.IO;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        private bool legacyPackedRecords;
        private int legacyTableXorLength;
        private bool UsesXorPrefixCipher => this.legacyPackedRecords || this.legacyLayout == LegacyLayoutKind.Header104Reordered || this.legacyLayout == LegacyLayoutKind.Header104Wide;

        private bool IsValidLegacyProxy(byte[] decoded, uint[] table)
        {
            if (decoded.Length != 8 || (BitConverter.ToUInt32(decoded, 0) != 656676094U && decoded[0] != 255)) return false;
            uint target = (BitConverter.ToUInt32(decoded, 4) ^ this.DataStructure.Encryption_Dword ^ this.DataStructure.ProtectionSettings) & 0xFFFFFF;
            return target > 0 && target <= table.Length && (table[target - 1] >> 28 == 4 || table[target - 1] >> 28 == 12);
        }

        private void DecodeLegacyTablePrefix(int defaultLength)
        {
            this.legacyTableXorLength = defaultLength;
            byte[] original = (byte[])this.DataStructure._MethodsOffsetTable.Clone();
            if (defaultLength != 0) base.XorSelf(this.DataStructure._MethodsOffsetTable, 0, defaultLength);
            if (this.legacyLayout == LegacyLayoutKind.Header104Permuted)
            {
                this.legacyPackedRecords = true;
                if (!ValidLegacyTable(this.DataStructure._MethodsOffsetTable))
                    throw new InvalidDataException("重排 104 字节布局的方法表未通过全部描述符校验。");
                return;
            }
            if (this.legacyLayout != LegacyLayoutKind.Header112Standard && this.legacyLayout != LegacyLayoutKind.Header104Standard) return;
            if (ValidLegacyTable(this.DataStructure._MethodsOffsetTable)) return;
            byte[] selected = null;
            bool selectedPacked = false;
            int selectedLength = defaultLength;
            foreach (int length in new[] { defaultLength, 9 }.Distinct())
                foreach (bool packed in new[] { false, true })
                {
                    if (packed && this.legacyLayout != LegacyLayoutKind.Header104Standard) continue;
                    byte[] candidate = (byte[])original.Clone();
                    if (length != 0) base.XorSelf(candidate, 0, length);
                    this.legacyPackedRecords = packed;
                    if (!ValidLegacyTable(candidate)) continue;
                    if (selected != null && (selectedPacked != packed || !selected.SequenceEqual(candidate)))
                        throw new InvalidDataException("历史方法表或描述符格式有多个有效候选。");
                    selected = candidate; selectedPacked = packed; selectedLength = length;
                }
            this.legacyPackedRecords = selectedPacked;
            if (selected == null) throw new InvalidDataException("历史方法表未通过全部描述符校验。");
            this.DataStructure._MethodsOffsetTable = selected;
            this.legacyTableXorLength = selectedLength;
            Console.WriteLine("PROBE 历史方法表已通过全部描述符校验；xorLength=" + selectedLength + " packed=" + selectedPacked);
        }

        private bool ValidLegacyTable(byte[] table)
        {
            try
            {
                int descriptors = 0;
                for (int i = 0; i < table.Length / 4; i++)
                {
                    uint item = BitConverter.ToUInt32(table, i * 4), kind = item >> 28;
                    if (item == 0 || item >> 24 == 0xF8 || kind == 6 || kind == 12) continue;
                    if (kind != 0 && kind != 1 && kind != 2 && kind != 4) return false;
                    uint mask = kind == 2 ? this.DataStructure.ProtectionSettings : this.DataStructure.Encryption_Dword;
                    if (kind == 4) mask ^= this.value3;
                    
                    
                    uint rva = (item ^ mask) & 0x0FFFFFFF;
                    if (!ValidLegacyRecordRva(rva) && !ValidLegacyRecordRva((item ^ mask) & 0xFFFFFF)) return false;
                    descriptors++;
                }
                return descriptors >= 3;
            }
            catch (IOException) { return false; }
            catch (ArgumentException) { return false; }
            catch (OverflowException) { return false; }
        }

        private uint ResolveLegacyRecordRva(uint item, uint xor)
        {
            uint preferred = (item ^ xor) & 0x0FFFFFFF;
            if (ValidLegacyRecordRva(preferred)) return preferred;
            var matches = new HashSet<uint>();
            foreach (uint key in new[] { xor, this.DataStructure.Encryption_Dword, this.DataStructure.ProtectionSettings })
            {
                uint rva = (item ^ key) & 0xFFFFFF;
                if (ValidLegacyRecordRva(rva)) matches.Add(rva);
            }
            if (matches.Count != 1) throw new InvalidDataException("无法唯一定位历史方法记录。");
            foreach (uint rva in matches) return rva;
            throw new InvalidDataException("无有效方法记录。");
        }

        private bool ValidLegacyRecordRva(uint rva)
        {
            uint raw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva);
            if (raw == 0 || (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)raw) != rva || (ulong)raw + 6 > this.reader.Length) return false;
            this.reader.Position = raw;
            uint descriptor = this.reader.ReadUInt32();
            if ((descriptor & 255) == 0xFE)
            {
                this.reader.Position -= 2;
                return ((descriptor >> 8) & 127) <= 15 && this.reader.ReadUInt32() < this.UncompressedMethodsBufferLength;
            }
            return this.UsesXorPrefixCipher && (descriptor & 127) <= 15 &&
                ((ulong)descriptor >> 8) * 8 < this.UncompressedMethodsBufferLength;
        }

        private void ReadLegacyDescriptor(uint item, out byte cipher, out uint offset)
        {
            uint descriptor = this.reader.ReadUInt32();
            if ((descriptor & 255) == 0xFE)
            {
                cipher = (byte)(descriptor >> 8);
                this.reader.Position -= 2;
                offset = this.reader.ReadUInt32();
            }
            else if (this.UsesXorPrefixCipher)
            {
                cipher = (byte)descriptor;
                offset = checked((descriptor >> 8) * 8);
            }
            else throw new InvalidDataException("方法记录缺少 FE 标记。");
            if ((cipher & 0x80) != 0) offset = checked(offset + 4);
            if (UsesXorPrefixCipher && (!this.legacyPackedRecords || this.legacyLayout == LegacyLayoutKind.Header104Permuted) && (item & 0x08000000) != 0) offset = checked(offset + 4);
            cipher &= 127;
            if (cipher > 15 || offset >= this.DataStructure._MethodsData.Length)
                throw new InvalidDataException("方法记录的算法或偏移无效。");
        }

        private byte[] DecodeLegacyPackedMethod(byte[] encoded, methodInfo info, int length)
        {
            if (this.legacyLayout == LegacyLayoutKind.Header104Permuted)
                return DecodeValidatedLegacyPermuted(encoded, info.DecryptorType, decoded => ValidDecodedMethod(decoded, info), length);
            byte[] known = (byte[])encoded.Clone();
            DecryptXor(known, this.KeyBuff);
            try
            {
                DecryptData(known, info.DecryptorType, false);
                Array.Resize(ref known, length);
                if (ValidDecodedMethod(known, info)) return known;
            }
            catch (NotImplementedException) { }
            catch (NotSupportedException) { }
            byte[] selected = InferCipher(encoded, info.DecryptorType, decoded => {
                Array.Resize(ref decoded, length);
                return ValidDecodedMethod(decoded, info);
            }, length);
            Array.Resize(ref selected, length);
            return selected;
        }

        private byte[] DecodeValidatedLegacyPermuted(byte[] encoded, int id, Func<byte[], bool> valid, int length = -1)
        {
            CipherChoice cached;
            if (this.inferredCiphers.TryGetValue(id, out cached))
            {
                byte[] decoded = DecodeChoice(encoded, cached);
                if (length >= 0) Array.Resize(ref decoded, length);
                if (!valid(decoded)) throw new InvalidDataException("同一算法编号的多条记录校验不一致。");
                return decoded;
            }
            return InferCipher(encoded, id, valid, length);
        }
    }
}
