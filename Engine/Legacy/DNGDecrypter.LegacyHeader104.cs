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
        private void ParseLegacyHeader104(BinaryReader binaryReader)
        {
        if (this.legacyLayout == LegacyLayoutKind.Header104Permuted)
        {
            
            
            var w = new uint[26];
            for (int i = 0; i < w.Length; i++) w[i] = binaryReader.ReadUInt32();
            this.valueN4 = w[0]; this.value3 = w[1]; this.value1 = w[2]; this.value2 = w[7];
            this.DataStructure.Encryption_Dword = w[3];
            this.DataStructure.ResourceStructureOffset = w[4];
            this.DataStructure.ResourceCount = w[6] >> 16;
            this.DataStructure.StringsOffset = w[5];
            this.DataStructure.EncryptedStringsSize = w[13];
            this.DataStructure.MethodsDataOffset = w[9];
            this.DataStructure.KeyBuffOffset = w[18];
            this.DataStructure.MethodsCount = w[12];
            this.DataStructure.MethodsBufferLength = w[14];
            this.UncompressedMethodsBufferLength = w[19];
            this.DataStructure.LEHSize = w[8];
            this.LEHLocalsOffset = w[22];
            this.HvmTokenTableOffset = w[11];
            this.HvmTokenTableSize = w[16];
            return;
        }
        if (this.legacyLayout == LegacyLayoutKind.Header104Reordered || this.legacyLayout == LegacyLayoutKind.Header104Wide)
        {
            var w = new uint[26];
            for (int i = 0; i < w.Length; i++) w[i] = binaryReader.ReadUInt32();
            bool wide = this.legacyLayout == LegacyLayoutKind.Header104Wide;
            this.valueN4 = w[0]; this.value3 = w[1]; this.value1 = w[3];
            this.value2 = w[wide ? 6 : 8];
            this.DataStructure.Encryption_Dword = w[2];
            this.DataStructure.ResourceStructureOffset = w[wide ? 5 : 4];
            this.DataStructure.ResourceCount = w[wide ? 7 : 5] & 0xFFFF;
            this.DataStructure.MethodsDataOffset = w[wide ? 11 : 6];
            this.DataStructure.KeyBuffOffset = w[wide ? 20 : 16];
            this.UncompressedMethodsBufferLength = w[wide ? 21 : 17];
            this.DataStructure.StringsOffset = w[wide ? 4 : 7];
            this.DataStructure.LEHSize = w[wide ? 10 : 11];
            this.DataStructure.MethodsBufferLength = w[wide ? 12 : 10];
            this.DataStructure.MethodsCount = w[wide ? 14 : 18];
            this.DataStructure.EncryptedStringsSize = w[wide ? 15 : 19];
            this.LEHLocalsOffset = w[wide ? 25 : 15];
            this.HvmTokenTableOffset = w[wide ? 13 : 9];
            this.HvmTokenTableSize = w[wide ? 22 : 24];
            return;
        }
		if (this.legacyLayout == LegacyLayoutKind.Header104Standard)
		{
			this.valueN4 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
			ushort useless = binaryReader.ReadUInt16();
			this.DataStructure.ResourceCount = (uint)binaryReader.ReadUInt16();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			this.value2 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			uint useless2 = binaryReader.ReadUInt32();
			uint useless3 = binaryReader.ReadUInt32();
			uint useless4 = binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			uint useless5 = binaryReader.ReadUInt32();
			uint useless6 = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
			uint useless7 = binaryReader.ReadUInt32();
			uint useless8 = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			uint useless9 = binaryReader.ReadUInt32();
		}
		else if (this.legacyLayout == LegacyLayoutKind.Header104Reordered)
		{
			this.valueN4 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
			ushort useless = binaryReader.ReadUInt16();
			this.DataStructure.ResourceCount = (uint)binaryReader.ReadUInt16();
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.value2 = binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			uint useles2 = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			uint usless3 = binaryReader.ReadUInt32();
			uint usless4 = binaryReader.ReadUInt32();
			uint usless5 = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			uint usless6 = binaryReader.ReadUInt32();
			uint usless7 = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			uint usless8 = binaryReader.ReadUInt32();
			uint usless9 = binaryReader.ReadUInt32();
			uint usless10 = binaryReader.ReadUInt32();
		}
		else if (this.legacyLayout == LegacyLayoutKind.Header104Wide)
		{
			this.valueN4 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
			ushort useless = binaryReader.ReadUInt16();
			this.DataStructure.ResourceCount = (uint)binaryReader.ReadUInt16();
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.value2 = binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			uint useles2 = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			uint usless3 = binaryReader.ReadUInt32();
			uint usless4 = binaryReader.ReadUInt32();
			uint usless5 = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			uint usless6 = binaryReader.ReadUInt32();
			uint usless7 = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			uint usless8 = binaryReader.ReadUInt32();
			uint usless9 = binaryReader.ReadUInt32();
			uint usless10 = binaryReader.ReadUInt32();
		}
		else if (this.legacyLayout == LegacyLayoutKind.Header104Shifted)
		{
			this.valueN4 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
			ushort useless = binaryReader.ReadUInt16();
			this.DataStructure.ResourceCount = (uint)binaryReader.ReadUInt16();
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.value2 = binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			uint useles2 = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			uint usless3 = binaryReader.ReadUInt32();
			uint usless4 = binaryReader.ReadUInt32();
			uint usless5 = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			uint usless6 = binaryReader.ReadUInt32();
			uint usless7 = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			uint usless8 = binaryReader.ReadUInt32();
			uint usless9 = binaryReader.ReadUInt32();
			uint usless10 = binaryReader.ReadUInt32();
		}
        }
    }
}
