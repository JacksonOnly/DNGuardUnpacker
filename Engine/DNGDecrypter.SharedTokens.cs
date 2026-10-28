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
		public void InitializeEncryptionKeys()
		{
			this.blowfishInstance = new Blowfish(this.KeyBuff, this.DataStructure.Encryption_Dword ^ this.DataStructure.ProtectionSettings);
			byte[] array = new byte[this.KeyBuff.Length + 4];
			Buffer.BlockCopy(this.KeyBuff, 0, array, 0, this.KeyBuff.Length);
			Buffer.BlockCopy(BitConverter.GetBytes(this.DataStructure.Encryption_Dword), 0, array, array.Length - 4, 4);
			this.algoKey = this.InitializeEncryptionKey(array);
		}

		public byte[] InitializeEncryptionKey(byte[] hash_key)
		{
			byte[] array = new byte[256];
			byte[] array2 = new byte[256];
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = (byte)i;
				array2[i] = hash_key[i % hash_key.Length];
			}
			int num = 0;
			for (int j = 0; j < array.Length; j++)
			{
				int num2 = ((int)array2[j] + num + (int)array[j] + 1) & 255;
				int num3 = (int)array[num2];
				int num4 = (int)array[j];
				array[j] = (byte)num3;
				array[num2] = (byte)num4;
				num = num2;
			}
			return array;
		}

		private byte[] ReadHVMTable()
		{
			byte[] result;
			using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(this.DataStructure.LEH)))
			{
				binaryReader.BaseStream.Position = (long)((ulong)this.HvmTokenTableOffset);
				if (this.legacy112Layout)
				{
					if (this.HvmTokenTableOffset > this.DataStructure.LEH.Length)
						throw new InvalidDataException("Legacy token table outside LEH buffer.");
					return binaryReader.ReadBytes(this.DataStructure.LEH.Length - (int)this.HvmTokenTableOffset);
				}
				result = binaryReader.ReadBytes((int)this.HvmTokenTableSize);
			}
			return result;
		}

		private uint[] ParseHVMTableAtOffset(byte[] hvm_table, uint offset, uint size)
		{
			List<uint> list = new List<uint>();
			int num = 0;
			using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(hvm_table)))
			{
				binaryReader.BaseStream.Position = (long)((ulong)(offset >> 1));
				while ((long)num != (long)((ulong)size))
				{
					uint num2 = binaryReader.ReadUInt32();
					if ((num2 >> 28) - 3U < 5U)
					{
						if ((offset & 1U) == 0U)
						{
							list.Add(num2);
							num++;
						}
						else if ((offset & 1U) == 1U)
						{
							list.Add(num2);
							binaryReader.BaseStream.Position += 4L;
							num += 2;
						}
					}
					else
					{
						list.Add(num2);
						num++;
					}
				}
			}
			return list.ToArray();
		}

		private uint[] ReadLegacy112Tokens(uint offset, out uint count)
		{
			long cursor = (long)this.HvmTokenTableOffset + (offset >> 1);
			RequireModernRange(this.DataStructure.LEH, cursor, 4, 0, "legacy token count");
			count = BitConverter.ToUInt32(this.DataStructure.LEH, (int)cursor);
			RequireModernRange(this.DataStructure.LEH, cursor + 4, (long)count * 4, 0, "legacy tokens");
			var tokens = new List<uint>();
			for (uint physical = 0; physical < count; physical++)
			{
				uint token = BitConverter.ToUInt32(this.DataStructure.LEH, checked((int)(cursor + 4 + physical * 4L)));
				tokens.Add(token);
				if ((offset & 1U) != 0 && (token >> 28) - 3U < 5U)
				{
					if (++physical >= count) throw new InvalidDataException("Truncated legacy paired token.");
				}
			}
			return tokens.ToArray();
		}

		public override uint DecryptHVMToken(uint hvmToken, int hvm_counter, MethodsDecrypter.DecrypterBase.methodInfo mi)
		{
            if (EarlyInlineLayout)
            {
                if ((hvmToken >> 24) == 0x70) return hvmToken ^ checked((uint)hvm_counter);
                uint rid = (hvmToken ^ this.DataStructure.Encryption_Dword ^ checked((uint)hvm_counter)) & 0xFFFFFF;
                return (hvmToken & 0xFF000000) | rid;
            }
			if (this.modernLayout)
			{
				if ((hvmToken >> 24) == 0x70) return hvmToken;
                int logical = checked((int)(hvmToken & 0xFFFFF) - 4);
                if (mi.MethodHvmTokens == null) throw new InvalidDataException("Invalid modern HVM token table.");
                int[] indices = mi.ModernTokenIndices ?? BuildModernTokenIndices(mi.MethodHvmTokens, (mi.HvmTokenTableOffset & 1U) != 0);
                if (logical < 0 || logical >= indices.Length) throw new InvalidDataException("Invalid modern HVM token index.");
                int index = indices[logical];
                
                if (index < 0 || index >= mi.MethodHvmTokens.Length) throw new InvalidDataException("Invalid modern paired token index.");
				uint decoded = DecodeModernTokenBits(hvmToken, mi, index) ^ this.modernTokenSalt;
				uint kind = decoded >> 28;
				if (kind >= tokenBases.Length) throw new InvalidDataException("Invalid modern HVM token kind.");
				return tokenBases[kind] | ((decoded >> 6) & 0x3FFFFF);
			}
			uint result;
			if ((hvmToken & 4278190080U) == 1879048192U)
			{
				result = hvmToken;
			}
			else
			{
				int num = (int)(hvmToken & 1048575U);
				hvmToken = mi.MethodHvmTokens[hvm_counter - 1];
				byte[] bytes = BitConverter.GetBytes(hvmToken);
				byte[] array = new byte[bytes.Length];
				bytes.CopyTo(array, 0);
				bytes[0] = array[2];
				bytes[1] = array[0];
				bytes[2] = array[1];
				hvmToken = BitConverter.ToUInt32(bytes, 0);
				uint num2;
				if (base.IsCompatibilityModeEnabled())
				{
					num2 = (uint)((ulong)(this.DataStructure.ProtectionSettings ^ ((this.DataStructure.Encryption_Dword ^ (this.DataStructure.Encryption_Dword >> 8)) & 268435455U) ^ hvmToken) ^ (ulong)((long)num));
				}
				else
				{
					num2 = (uint)((ulong)(this.DataStructure.ProtectionSettings ^ (this.DataStructure.Encryption_Dword & 268435455U) ^ hvmToken) ^ (ulong)((long)num));
				}
				if (base.IsApplicationMode())
				{
					num2 ^= this.DataStructure.Encryption_Dword >> 16;
				}
				uint num3 = DNGDecrypter.tokenBases[(int)(num2 >> 28)] | ((num2 >> 6) & 4194303U);
				result = num3;
			}
			return result;
		}

        private uint DecodeModernTokenBits(uint token, methodInfo info, int index)
        {
            uint packed = info.MethodHvmTokens[index] ^ (info.HvmTokenTableSize + (uint)index);
            packed = (packed & 0xFF000000) | ((packed & 0xFFFF) << 8) | ((packed >> 16) & 255);
            uint decoded = packed ^ this.DataStructure.ProtectionSettings ^ (this.DataStructure.Encryption_Dword & 0xFFFFFFF) ^ (token & 0xFFFFF);
            if (Profile.CompatibilityTokenMask && IsCompatibilityModeEnabled()) decoded ^= (this.DataStructure.Encryption_Dword >> 8) & 0xFFFFFFF;
            if (IsApplicationMode()) decoded ^= this.DataStructure.Encryption_Dword >> 16;
            return decoded;
        }
    }
}
