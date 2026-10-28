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
        private void ParseLegacyHeader124(BinaryReader binaryReader, byte[] array3)
        {

		if (this.legacyLayout == LegacyLayoutKind.Header124Direct)
		{
			this.valueN4 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.value2 = this.value3;
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
			uint unknows = binaryReader.ReadUInt32();
			uint usless3 = binaryReader.ReadUInt32();
			uint useless4 = binaryReader.ReadUInt32();
			uint useless5 = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			uint useless2 = binaryReader.ReadUInt32();
			uint unknownnewval = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			uint useless7 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			uint useless8 = binaryReader.ReadUInt32();
			uint usless5 = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			uint usless8 = binaryReader.ReadUInt32();
			uint usless9 = binaryReader.ReadUInt32();
			uint uselss11 = binaryReader.ReadUInt32();
			uint uselss12 = binaryReader.ReadUInt32();
			uint uselss13 = binaryReader.ReadUInt32();
			uint usless11 = binaryReader.ReadUInt32();
		}
		else if (this.legacyLayout == LegacyLayoutKind.Header124Alternate)
		{

			this.valueN4 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.value2 = this.value3;
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			uint unknown = binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			uint useless2 = binaryReader.ReadUInt32();
			uint useless4 = binaryReader.ReadUInt32();
			uint useless5 = binaryReader.ReadUInt32();
			uint useless6 = binaryReader.ReadUInt32();
			uint useless7 = binaryReader.ReadUInt32();
			uint useless1e = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			uint unknwom = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			uint useless8 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			uint usless9 = binaryReader.ReadUInt32();
			uint uselss11 = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
			uint uselss13 = binaryReader.ReadUInt32();
			uint usless11 = binaryReader.ReadUInt32();
			this.DataStructure.ResourceCount = 0U;
		}
		else if (this.legacyLayout == LegacyLayoutKind.Header124Unencrypted || (array3 != null && array3.Length >= 4 && BitConverter.ToUInt32(array3, 0) == 0x0020007C))
		{

			this.legacyLayout = LegacyLayoutKind.Header124Unencrypted;
			this.valueN4 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			uint useless02 = binaryReader.ReadUInt32();
			uint useless03 = binaryReader.ReadUInt32();
			uint useless04 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			uint useless06 = binaryReader.ReadUInt32();
			uint encDword = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = 0U;
			uint useless08 = binaryReader.ReadUInt32();
			uint runHvmRva = binaryReader.ReadUInt32();
			uint useless10 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			uint v12 = binaryReader.ReadUInt32();
			uint v13 = binaryReader.ReadUInt32();
			uint useless14 = binaryReader.ReadUInt32();
			uint useless15 = binaryReader.ReadUInt32();
			uint useless16 = binaryReader.ReadUInt32();
			uint useless17 = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			uint useless21 = binaryReader.ReadUInt32();
			uint v22 = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			uint useless24 = binaryReader.ReadUInt32();
			uint useless25 = binaryReader.ReadUInt32();
			uint useless26 = binaryReader.ReadUInt32();
			uint useless27 = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
			uint useless29 = binaryReader.ReadUInt32();
			uint v30 = binaryReader.ReadUInt32();

			this.value1 = this.value3;
			this.value2 = this.value3;
			this.DataStructure.KeyBuffOffset = (v12 ^ this.value3 ^ v22) & 0x0FFFFFFFU;
			this.DataStructure.MethodsDataOffset = this.DataStructure.KeyBuffOffset;
			this.DataStructure.MethodsBufferLength = this.UncompressedMethodsBufferLength;
			this.DataStructure.ResourceCount = 0U;
			this.DataStructure.StringsOffset = 0U;
			this.DataStructure.EncryptedStringsSize = 0U;
		}
        }
    }
}
