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
        private void ParseLegacyHeader152(BinaryReader binaryReader)
        {
		if (this.legacyLayout == LegacyLayoutKind.Header152)
		{
			uint wtf = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.value2 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			uint usless12 = binaryReader.ReadUInt32();
			this.valueN4 = binaryReader.ReadUInt32();
			uint usless3 = binaryReader.ReadUInt32();
			uint usless4 = binaryReader.ReadUInt32();
			uint usless5 = binaryReader.ReadUInt32();
			uint num = (this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32());
			uint usless6 = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
			this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
			uint usless7 = binaryReader.ReadUInt32();
			num = (this.DataStructure.MethodsCount = binaryReader.ReadUInt32());
			uint usless9 = binaryReader.ReadUInt32();
			uint usless10 = binaryReader.ReadUInt32();
			uint usless13 = binaryReader.ReadUInt32();
			this.DataStructure.LocalsAndEHOffset = binaryReader.ReadUInt32();
			uint usless14 = binaryReader.ReadUInt32();
			uint usless13_2 = binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
			uint usless11 = binaryReader.ReadUInt32();
			uint usless15 = binaryReader.ReadUInt32();
			uint usless16 = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			uint usless17 = binaryReader.ReadUInt32();
			uint usless18 = binaryReader.ReadUInt32();
			uint usless19 = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			uint usless20 = binaryReader.ReadUInt32();
		}
        }
    }
}
