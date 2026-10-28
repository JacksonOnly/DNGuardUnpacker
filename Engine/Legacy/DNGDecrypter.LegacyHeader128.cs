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
        private void ParseLegacyHeader128(BinaryReader binaryReader)
        {
		this.valueN4 = binaryReader.ReadUInt32();
		this.value3 = binaryReader.ReadUInt32();
		this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
		this.value1 = binaryReader.ReadUInt32();
		this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
		binaryReader.ReadUInt16();
		this.DataStructure.ResourceCount = (uint)binaryReader.ReadUInt16();
		this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
		this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
		this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
		this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
		this.DataStructure.LEHSize = binaryReader.ReadUInt32();
		this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
		this.value2 = binaryReader.ReadUInt32();
		this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
		uint useless10 = binaryReader.ReadUInt32();
		uint useless2 = binaryReader.ReadUInt32();
		uint useless3 = binaryReader.ReadUInt32();
		this.LEHLocalsOffset = binaryReader.ReadUInt32();
		uint useless4 = binaryReader.ReadUInt32();
		uint useless5 = binaryReader.ReadUInt32();
		this.HvmTokenTableOffset = binaryReader.ReadUInt32();
		this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
		uint useless6 = binaryReader.ReadUInt32();
		uint useless7 = binaryReader.ReadUInt32();
		this.HvmTokenTableSize = binaryReader.ReadUInt32();
		uint useless8 = binaryReader.ReadUInt32();
		this.valueN5 = 0U;
		if (this.StructSize >= 124)
		{
			uint useless9 = binaryReader.ReadUInt32();
			uint useless11 = binaryReader.ReadUInt32();
			uint useless12 = binaryReader.ReadUInt32();
			uint useless13 = binaryReader.ReadUInt32();
			this.valueN5 = binaryReader.ReadUInt32();
		}
		long Pos = binaryReader.BaseStream.Position;
        }
    }
}
