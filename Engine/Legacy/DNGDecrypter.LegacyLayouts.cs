using System;
using System.Collections.Generic;
using System.IO;
using dnlib.PE;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        public override void ParseStructure()
        {
            if (this.DataSection == null) throw new InvalidDataException("未找到 DNGuard 数据节。");
            byte[] header = null;
            int matches = 0;
            for (int size = 4; size <= 396 && (ulong)this.DataOffset + (uint)size <= this.reader.Length; size += 4)
            {
                byte[] candidate = null;
                if (GetStructSize(size, ref candidate) == 0) continue;
                this.StructSize = size;
                header = candidate;
                matches++;
            }
            if (matches != 1) throw new NotSupportedException("无法通过校验和唯一确定 DNGuard 数据头长度。");
            if (TryModernStructure(header)) return;
            LegacyLayoutKind selected = LegacyLayoutKind.Unknown;
            bool preserve112 = false;
            foreach (var candidate in LegacyCandidates(this.StructSize))
            {
                var probe = new DNGDecrypter(this.module, this.externalMethods);
                try
                {
                    probe.ParseLegacyCandidate(header, candidate);
                    if (!probe.ValidateLegacyCandidate()) continue;
                }
                catch (InvalidDataException error) { if (ConsoleLog.Verbose) Console.WriteLine("CANDIDATE 候选 " + candidate + "：" + error.Message); continue; }
                catch (IOException) { continue; }
                catch (ArgumentException) { continue; }
                catch (OverflowException) { continue; }
                if (selected != LegacyLayoutKind.Unknown)
                    throw new InvalidDataException("多个历史布局通过校验，拒绝不明确的候选。");
                selected = candidate;
                preserve112 = probe.legacy112Layout;
            }
            if (selected == LegacyLayoutKind.Unknown)
                throw new NotSupportedException("没有通过密钥、方法数和数据块校验的布局；请运行 probe 检查候选字段。");
            this.legacy112Layout = preserve112;
            ParseLegacyCandidate(header, selected);
            Console.WriteLine("LAYOUT " + selected + " headerBytes=" + this.StructSize + " settings=" + this.DataStructure.ProtectionSettings.ToString("X8"));
        }

        private static IEnumerable<LegacyLayoutKind> LegacyCandidates(int size)
        {
            switch (size)
            {
                case 104: return new[] { LegacyLayoutKind.Header104Standard, LegacyLayoutKind.Header104Reordered, LegacyLayoutKind.Header104Wide, LegacyLayoutKind.Header104Shifted, LegacyLayoutKind.Header104Permuted };
                case 108: return new[] { LegacyLayoutKind.Header108 };
                case 112: return new[] { LegacyLayoutKind.Header112Standard, LegacyLayoutKind.Header112Alternate };
                case 124: return new[] { LegacyLayoutKind.Header124Direct, LegacyLayoutKind.Header124Alternate, LegacyLayoutKind.Header124Unencrypted };
                case 128: return new[] { LegacyLayoutKind.Header128, LegacyLayoutKind.Header128Inline };
                case 152: return new[] { LegacyLayoutKind.Header152, LegacyLayoutKind.Header152Inline, LegacyLayoutKind.Header152Tokens };
                case 156: return new[] { LegacyLayoutKind.Header156Inline };
                case 160: return new[] { LegacyLayoutKind.Header160Separated, LegacyLayoutKind.Header160Permuted, LegacyLayoutKind.Header160Tokens };
                default: return new LegacyLayoutKind[0];
            }
        }

        private void ParseLegacyCandidate(byte[] header, LegacyLayoutKind kind)
        {
            this.StructSize = header.Length;
            this.legacyLayout = kind;
            if (EarlyCipherLayout) { ParseEarlyHeader(header); return; }
            if (kind == LegacyLayoutKind.Header112Standard && BitConverter.ToUInt32(header, 0) == 0x00190070U)
                this.legacy112Layout = true;
            using (var reader = new BinaryReader(new MemoryStream(header)))
            {
                switch (header.Length)
                {
                    case 104: ParseLegacyHeader104(reader); break;
                    case 108: ParseLegacyHeader108(reader); break;
                    case 112: ParseLegacyHeader112(reader); break;
                    case 124: ParseLegacyHeader124(reader, header); break;
                    case 128: ParseLegacyHeader128(reader); break;
                    case 152: ParseLegacyHeader152(reader); break;
                    case 160: ParseLegacyHeader160(reader); break;
                }
            }
            if (kind == LegacyLayoutKind.Header124Unencrypted)
                this.DataStructure.ProtectionSettings = 0;
            else if (kind == LegacyLayoutKind.Header152)
                this.DataStructure.ProtectionSettings = this.value1 ^ this.value3 ^ this.valueN4 ^ this.DataStructure.Encryption_Dword;
            else
                this.DataStructure.ProtectionSettings = this.value1 ^ this.value3 ^ this.DataStructure.Encryption_Dword;
            if (kind != LegacyLayoutKind.Header124Unencrypted)
                this.DataStructure.MethodsDataOffset ^= this.value2;
            if (kind == LegacyLayoutKind.Header160Separated || kind == LegacyLayoutKind.Header160Permuted)
                this.DataStructure.LocalsAndEHOffset ^= this.value3 ^ this.DataStructure.Encryption_Dword;
            if (kind != LegacyLayoutKind.Header124Unencrypted && header.Length >= 124 && (this.DataStructure.ProtectionSettings & 0xFFFF0000U) != 0)
                this.DataStructure.ProtectionSettings = this.valueN4 ^ this.valueN5 ^ this.value3 ^ this.DataStructure.Encryption_Dword;
            this.DataStructure.ProtectionFeatures = (ProtectSettings)(this.DataStructure.ProtectionSettings & 4095U);
            if (IsEnterpriseEdition())
            {
                this.DataStructure.KeyBuffOffset ^= this.DataStructure.Encryption_Dword;
                if (!VerifyModernKeyAtRva(this.DataStructure.KeyBuffOffset, this.DataStructure.Encryption_Dword))
                    throw new InvalidDataException("布局候选的密钥校验失败。");
                this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.KeyBuffOffset);
                this.KeyBuff = this.reader.ReadBytes(16);
                this.DataStructure.LocalsAndEHOffset ^= this.DataStructure.ProtectionSettings;
                this.DataStructure.MethodsDataOffset ^= this.DataStructure.ProtectionSettings;
            }
        }

        private bool ContiguousLegacyLeh => !EarlyCipherLayout && this.legacyLayout != LegacyLayoutKind.Header128 &&
            this.legacyLayout != LegacyLayoutKind.Header160Separated && this.legacyLayout != LegacyLayoutKind.Header160Permuted;

        private bool ValidateLegacyCandidate()
        {
            if (this.DataStructure.MethodsCount == 0 || this.DataStructure.MethodsCount > this.module.Metadata.TablesStream.MethodTable.Rows ||
                this.DataStructure.MethodsBufferLength == 0 || this.DataStructure.ResourceCount > this.module.Metadata.TablesStream.ManifestResourceTable.Rows ||
                (this.DataStructure.ProtectionSettings & 0xFFF80000U) != 0) return false;
            ValidateMethodDataBounds();
            if (this.legacyLayout == LegacyLayoutKind.Header160Tokens) return ValidateLegacyHeader160Tokens();
            if (IsEnterpriseEdition())
            {
                if (this.externalMethods != null) return IsExternalBlockLayout(this.DataStructure.MethodsBufferLength, this.DataStructure.LEHSize);
                uint raw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.MethodsDataOffset);
                this.reader.Position = checked(raw + this.DataStructure.MethodsCount * 4);
                if (this.reader.ReadUInt32() != this.UncompressedMethodsBufferLength || this.UncompressedMethodsBufferLength > 64 * 1024 * 1024) return false;
            }
            if (this.legacyLayout == LegacyLayoutKind.Header104Permuted)
            {
                if (!IsHVMTechnologyEnabled() || this.UncompressedMethodsBufferLength == 0 || this.DataStructure.LEHSize < 4) return false;
                uint raw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.MethodsDataOffset);
                this.reader.Position = checked(raw + this.DataStructure.MethodsCount * 4 + this.DataStructure.MethodsBufferLength);
                uint expandedLeh = this.reader.ReadUInt32();
                if (expandedLeh > 64 * 1024 * 1024 || this.LEHLocalsOffset > this.HvmTokenTableOffset ||
                    (ulong)this.HvmTokenTableOffset + this.HvmTokenTableSize != expandedLeh) return false;
            }
            return true;
        }
    }
}
