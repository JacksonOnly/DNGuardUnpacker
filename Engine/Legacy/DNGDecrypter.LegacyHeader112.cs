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
        private bool legacy112Layout;
        private void DecodeLegacy112Cipher(byte[] data, int id)
        {

            int cipher;
            switch (id)
            {
                case 0: cipher = 0; break;
                case 1: cipher = 2; break;
                case 2: cipher = 1; break;
                case 6: cipher = 5; break;
                case 7: cipher = 6; break;
                case 8: cipher = 4; break;
                case 9: cipher = 11; break;
                case 10: cipher = 13; break;
                case 11: cipher = 9; break;
                case 12: cipher = 10; break;
                case 13: cipher = 12; break;
                case 14: cipher = 14; break;
                case 15: cipher = 15; break;
                default: throw new NotSupportedException("Unverified legacy 112-byte cipher ID " + id);
            }
            base.DecryptXor(data, this.KeyBuff);
            this.DecryptData(data, cipher, false);
        }

        private LegacyLayoutKind IdentifyLegacyHeader112(byte[] bytes)
        {
            if (bytes.Length != 112 || BitConverter.ToUInt32(bytes, 0) != 0x00190070U)
                return LegacyLayoutKind.Unknown;
            var w = new uint[28];
            Buffer.BlockCopy(bytes, 0, w, 0, bytes.Length);
            uint settings = w[1] ^ w[2] ^ w[3];
            if ((settings & 0xFFFF0000U) != 0 || w[3] == 0) return LegacyLayoutKind.Unknown;
            bool standard = IsLegacyHeader112Layout(w, settings, false);
            bool alternate = IsLegacyHeader112Layout(w, settings, true);
            if (standard == alternate)
                throw new InvalidDataException("No unique validated legacy 112-byte layout.");
            this.legacy112Layout = standard;
            Console.WriteLine("LAYOUT legacy112 variant=" + (alternate ? "alternate" : "standard") + " settings=" + settings.ToString("X8"));
            return alternate ? LegacyLayoutKind.Header112Alternate : LegacyLayoutKind.Header112Standard;
        }

        private bool IsLegacyHeader112Layout(uint[] w, uint settings, bool alternate)
        {
            uint count = w[alternate ? 11 : 14];
            uint expanded = w[12], compressed = w[26], leh = w[alternate ? 10 : 11];
            if (count == 0 || count > this.module.Metadata.TablesStream.MethodTable.Rows ||
                compressed < 4 || expanded == 0 || expanded > 64U * 1024U * 1024U)
                return false;
            uint keyRva = w[alternate ? 7 : 10] ^ w[3];
            uint methodsRva = w[alternate ? 22 : 25] ^ w[alternate ? 6 : 5] ^ settings;
            uint raw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)methodsRva);
            if (raw == 0 || (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)raw) != methodsRva ||
                (ulong)raw + (ulong)count * 4UL + compressed + leh > this.reader.Length ||
                !VerifyModernKeyAtRva(keyRva, w[3])) return false;
            this.reader.Position = checked(raw + count * 4U);
            return this.reader.ReadUInt32() == expanded;
        }

        private void ParseLegacyHeader112(BinaryReader binaryReader)
        {
		if (this.legacyLayout == LegacyLayoutKind.Header112Alternate)
		{
			this.valueN4 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			uint useless10 = binaryReader.ReadUInt32();
			uint useless2 = binaryReader.ReadUInt32();
			this.value2 = binaryReader.ReadUInt32();
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
			uint usless3 = binaryReader.ReadUInt32();
			uint useless7 = binaryReader.ReadUInt32();
			uint useless8 = binaryReader.ReadUInt32();
			uint usless5 = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			uint usless8 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			uint usless9 = binaryReader.ReadUInt32();
			uint uselss11 = binaryReader.ReadUInt32();
			uint uselss12 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			uint uselss13 = binaryReader.ReadUInt32();
		}
		else if (this.legacyLayout == LegacyLayoutKind.Header112Standard)
		{
			this.valueN4 = binaryReader.ReadUInt32();
			this.value3 = binaryReader.ReadUInt32();
			this.value1 = binaryReader.ReadUInt32();
			this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
			uint useless2 = binaryReader.ReadUInt32();
			this.value2 = binaryReader.ReadUInt32();
			this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
			this.LEHLocalsOffset = binaryReader.ReadUInt32();
			this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
			this.DataStructure.LEHSize = binaryReader.ReadUInt32();
			this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
			this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
			uint usless3 = binaryReader.ReadUInt32();
			uint usless5 = binaryReader.ReadUInt32();
			this.HvmTokenTableOffset = binaryReader.ReadUInt32();
			uint useless7 = binaryReader.ReadUInt32();
			uint useless8 = binaryReader.ReadUInt32();
			uint usless6 = binaryReader.ReadUInt32();
			uint usless7 = binaryReader.ReadUInt32();
			this.HvmTokenTableSize = binaryReader.ReadUInt32();
			uint usless8 = binaryReader.ReadUInt32();
			uint usless9 = binaryReader.ReadUInt32();
			this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
			this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
			uint usless10 = binaryReader.ReadUInt32();
			this.DataStructure.EncryptedStringsSize = 0U;
			this.DataStructure.ResourceCount = 0U;
			if (this.legacy112Layout)
			{
				binaryReader.BaseStream.Position = 20 * 4;
				this.LEHLocalsOffset = binaryReader.ReadUInt32();
			}
		}
        }
    }
}
