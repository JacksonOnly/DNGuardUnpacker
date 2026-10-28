using System;
using System.IO;
using dnlib.DotNet;
using dnlib.PE;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        private bool EarlyInlineLayout => this.legacyLayout == LegacyLayoutKind.Header128Inline ||
            this.legacyLayout == LegacyLayoutKind.Header156Inline || this.legacyLayout == LegacyLayoutKind.Header152Inline;
        private bool EarlyTokenLayout => this.legacyLayout == LegacyLayoutKind.Header152Tokens ||
            this.legacyLayout == LegacyLayoutKind.Header160Tokens;
        private bool EarlyCipherLayout => EarlyInlineLayout || EarlyTokenLayout;
        protected override bool HvmTokenFormatEnabled => !EarlyInlineLayout;
        public override bool UsesEncodedMetadataTokens => EarlyInlineLayout || base.UsesEncodedMetadataTokens;
        private System.Collections.Generic.Dictionary<uint, string> earlyInlineStrings;

        public override string ReadInlineUserString(uint token)
        {
            if (!EarlyInlineLayout || this.DataStructure.StringsOffset == 0)
                return base.ReadInlineUserString(token);
            
            
            uint position = token & 0xFFFFFF;
            if ((token >> 24) != 0x70 || position == 0 || position > this.DataStructure.EncryptedStringsSize)
                throw new InvalidDataException("Early inline string offset outside protected string block.");
            uint offset = position - 1;
            if (earlyInlineStrings == null)
            {
                var records = new System.Collections.Generic.Dictionary<uint, string>();
                var strings = this.module.Metadata.PEImage.CreateReader((RVA)this.DataStructure.StringsOffset, this.DataStructure.EncryptedStringsSize);
                var utf16 = new System.Text.UnicodeEncoding(false, false, true);
                while (strings.Position < strings.Length)
                {
                    uint start = strings.Position, length = strings.ReadCompressedUInt32();
                    
                    if (length == 0 && start == strings.Length - 1) break;
                    if (length == 0 || (length & 1) == 0 || (ulong)strings.Position + length > strings.Length)
                        throw new InvalidDataException("Invalid early inline string block boundary: offset=" + start + " length=" + length + " size=" + strings.Length + ".");
                    string text = utf16.GetString(strings.ReadBytes(checked((int)length - 1)));
                    if (strings.ReadByte() > 1) throw new InvalidDataException("Invalid early inline string terminal flag.");
                    records.Add(start, text);
                }
                earlyInlineStrings = records;
            }
            string value;
            if (!earlyInlineStrings.TryGetValue(offset, out value))
                throw new InvalidDataException("Early inline string token does not identify a record boundary.");
            return value;
        }

        private uint ResolveEarlyInlineProxy(uint sourceRid, uint[] table, out uint targetRid)
        {
            if (sourceRid == 0 || sourceRid > table.Length || table[sourceRid - 1] >> 28 != 2)
                throw new InvalidDataException("内联代理的源 RID 或记录种类无效。");
            targetRid = (table[sourceRid - 1] ^ this.DataStructure.Encryption_Dword ^ sourceRid) & 0xFFFFFF;
            if (targetRid == 0 || targetRid > table.Length || table[targetRid - 1] >> 28 != 5)
                throw new InvalidDataException("内联代理的目标 RID 或记录种类无效。");
            var source = this.module.ResolveMethod(sourceRid);
            var target = this.module.ResolveMethod(targetRid);
            if (source == null || target == null || source.DeclaringType != target.DeclaringType ||
                !CanReplaceModernProxy(target, source, new SigComparer()))
                throw new InvalidDataException("内联代理目标的所属类型或签名不匹配：源 RID=" + sourceRid + "，目标 RID=" + targetRid + "。");
            uint rva = (table[targetRid - 1] ^ this.DataStructure.Encryption_Dword ^ sourceRid) & 0xFFFFFF;
            if (!ValidLegacyRecordRva(rva)) throw new InvalidDataException("内联代理目标的方法记录无效。");
            return rva;
        }

        private void ParseEarlyHeader(byte[] header)
        {
            var w = new uint[header.Length / 4];
            Buffer.BlockCopy(header, 0, w, 0, header.Length);
            if (this.legacyLayout == LegacyLayoutKind.Header160Tokens)
            {
                this.value3 = w[1]; this.value1 = w[3];
                this.DataStructure.Encryption_Dword = w[2];
                this.DataStructure.ProtectionSettings = w[1] ^ w[2] ^ w[3];
                this.DataStructure.ProtectionFeatures = (ProtectSettings)(this.DataStructure.ProtectionSettings & 4095);
                this.DataStructure.KeyBuffOffset = w[13] ^ w[2];
                if (!VerifyModernKeyAtRva(this.DataStructure.KeyBuffOffset, w[2])) throw new InvalidDataException("160 字节令牌布局的密钥校验失败。");
                this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.KeyBuffOffset);
                this.KeyBuff = this.reader.ReadBytes(16);
                this.DataStructure.MethodsDataOffset = w[18] ^ w[1] ^ this.DataStructure.ProtectionSettings;
                this.DataStructure.MethodsCount = w[7];
                this.UncompressedMethodsBufferLength = w[19];
                this.DataStructure.MethodsBufferLength = w[10];
                this.DataStructure.LocalsAndEHOffset = w[26] ^ w[1] ^ w[2] ^ this.DataStructure.ProtectionSettings;
                this.DataStructure.LEHSize = w[8];
                this.DataStructure.StringsOffset = checked(w[4] + 1);
                this.DataStructure.EncryptedStringsSize = w[34];
                
                
                if (w[11] != 0 || w[12] != 0) throw new InvalidDataException("160 字节令牌布局的资源字段尚未验证。");
                this.DataStructure.ResourceStructureOffset = w[23];
                this.DataStructure.ResourceCount = w[12];
                this.LEHLocalsOffset = w[32]; this.HvmTokenTableOffset = w[28]; this.HvmTokenTableSize = w[33];
                return;
            }
            if (this.legacyLayout != LegacyLayoutKind.Header128Inline)
            {
                ParseReorderedEarlyHeader(w);
                return;
            }
            this.valueN4 = w[0]; this.value3 = w[1]; this.value1 = w[0];
            this.DataStructure.Encryption_Dword = w[2];
            this.DataStructure.ProtectionSettings = w[0] ^ w[1] ^ w[2] ^ w[30];
            this.DataStructure.ProtectionFeatures = (ProtectSettings)(this.DataStructure.ProtectionSettings & 4095);
            this.DataStructure.KeyBuffOffset = w[11] ^ w[2];
            if (!VerifyModernKeyAtRva(this.DataStructure.KeyBuffOffset, w[2])) throw new System.IO.InvalidDataException("早期布局密钥校验失败。");
            this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.KeyBuffOffset);
            this.KeyBuff = this.reader.ReadBytes(16);
            this.DataStructure.MethodsDataOffset = w[7] ^ w[1];
            this.DataStructure.MethodsCount = w[13];
            this.UncompressedMethodsBufferLength = w[4];
            this.DataStructure.MethodsBufferLength = w[5];
            this.DataStructure.LocalsAndEHOffset = w[22] ^ w[1] ^ w[2] ^ this.DataStructure.ProtectionSettings;
            this.DataStructure.LEHSize = w[23];
            this.DataStructure.StringsOffset = w[8] + 1;
            this.DataStructure.EncryptedStringsSize = w[21];
            this.DataStructure.ResourceStructureOffset = w[29];
            this.DataStructure.ResourceCount = w[28];
        }

        private void ParseReorderedEarlyHeader(uint[] w)
        {
            bool tokens = EarlyTokenLayout, wide = this.legacyLayout == LegacyLayoutKind.Header156Inline;
            uint encryption = w[wide ? 7 : 2];
            this.value3 = w[wide ? 3 : tokens ? 3 : 4];
            this.valueN4 = w[0]; this.value1 = w[1];
            this.DataStructure.Encryption_Dword = encryption;
            this.DataStructure.ProtectionSettings = w[1] ^ this.value3 ^ encryption;
            this.DataStructure.ProtectionFeatures = (ProtectSettings)(this.DataStructure.ProtectionSettings & 4095);
            this.DataStructure.KeyBuffOffset = w[wide ? 6 : tokens ? 37 : 7] ^ encryption;
            if (!VerifyModernKeyAtRva(this.DataStructure.KeyBuffOffset, encryption)) throw new System.IO.InvalidDataException("早期布局密钥校验失败。");
            this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.KeyBuffOffset);
            this.KeyBuff = this.reader.ReadBytes(16);
            this.DataStructure.MethodsDataOffset = w[wide ? 24 : tokens ? 29 : 34] ^ this.value3;
            this.DataStructure.MethodsCount = w[wide ? 2 : tokens ? 11 : 8];
            this.UncompressedMethodsBufferLength = w[wide ? 9 : tokens ? 20 : 3];
            this.DataStructure.MethodsBufferLength = w[wide ? 11 : tokens ? 14 : 10];
            this.DataStructure.LocalsAndEHOffset = w[wide ? 35 : tokens ? 28 : 33] ^ w[1];
            this.DataStructure.LEHSize = w[wide ? 14 : tokens ? 12 : 13];
            this.DataStructure.StringsOffset = w[wide ? 10 : tokens ? 10 : 9] + 1U;
            this.DataStructure.EncryptedStringsSize = w[wide ? 21 : tokens ? 7 : 20];
            this.DataStructure.ResourceStructureOffset = w[wide ? 15 : tokens ? 9 : 14];
            this.DataStructure.ResourceCount = w[wide ? 13 : tokens ? 15 : 12];
            if (tokens) { this.LEHLocalsOffset = w[31]; this.HvmTokenTableOffset = w[32]; this.HvmTokenTableSize = w[33]; }
        }
    }
}
