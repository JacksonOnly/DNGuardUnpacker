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
        private void ParseLegacyHeader108(BinaryReader binaryReader)
        {
		if (this.legacyLayout == LegacyLayoutKind.Header108)
		{
			this.valueN4 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			uint useless10 = binaryReader.ReadUInt32();
			this.value2 = binaryReader.ReadUInt32();
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			uint useless2 = binaryReader.ReadUInt32();
			this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			uint usless3 = binaryReader.ReadUInt32();
			uint useless4 = binaryReader.ReadUInt32();
			uint useless7 = binaryReader.ReadUInt32();
			uint usless7 = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			uint usless8 = binaryReader.ReadUInt32();
			uint usless9 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			uint uselss11 = binaryReader.ReadUInt32();
			uint uselss12 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			uint uselss13 = binaryReader.ReadUInt32();
		}
        }
    }
}
