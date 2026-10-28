using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.IO;
using dnlib.PE;

using DNGuard_Unpacker.Versions;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        private bool ValidateLegacyHeader160Tokens()
        {
            if (!IsEnterpriseEdition() || !IsHVMTechnologyEnabled() || IsApplicationMode() ||
                this.DataStructure.MethodsBufferLength < 4 || this.DataStructure.LEHSize < 4 ||
                this.UncompressedMethodsBufferLength == 0 || this.UncompressedMethodsBufferLength > 64 * 1024 * 1024) return false;
            this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.MethodsDataOffset);
            byte[] table = this.reader.ReadBytes(checked((int)this.DataStructure.MethodsCount * 4));
            byte[] methods = this.reader.ReadBytes(checked((int)this.DataStructure.MethodsBufferLength));
            if (BitConverter.ToUInt32(methods, 0) != this.UncompressedMethodsBufferLength) return false;
            this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.LocalsAndEHOffset);
            byte[] leh = this.reader.ReadBytes(checked((int)this.DataStructure.LEHSize));
            uint expandedLeh = BitConverter.ToUInt32(leh, 0);
            if (expandedLeh == 0 || expandedLeh > 64 * 1024 * 1024 || this.LEHLocalsOffset > expandedLeh ||
                this.HvmTokenTableOffset > expandedLeh || this.HvmTokenTableSize > expandedLeh - this.HvmTokenTableOffset ||
                (this.HvmTokenTableSize & 3) != 0) return false;
            if (new LZAri().Decode(methods).Length != this.UncompressedMethodsBufferLength ||
                new LZAri().Decode(leh).Length != expandedLeh) return false;
            DecryptPrevXor(table, this.KeyBuff); XorSelf(table, 0, table.Length);
            if (!ValidLegacyTable(table)) return false;
            if (this.DataStructure.EncryptedStringsSize == 0) return true;
            uint stringsRaw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.StringsOffset);
            return stringsRaw != 0 && (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)stringsRaw) == this.DataStructure.StringsOffset &&
                (ulong)stringsRaw + this.DataStructure.EncryptedStringsSize <= this.reader.Length;
        }

        private void ParseLegacyHeader160(BinaryReader binaryReader)
        {
		if (this.legacyLayout == LegacyLayoutKind.Header160Separated)
		{
			binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			this.DataStructure.LocalsAndEHOffset = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			this.value2 = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
		}
		else if (this.legacyLayout == LegacyLayoutKind.Header160Permuted)
		{
			binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
			this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.DataStructure.LocalsAndEHOffset = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			binaryReader.ReadUInt32();
			this.value2 = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
		}
        }
    }
}
