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
		public byte[] DecodeModernCipher(byte[] encoded, int decryptorId)
		{
			return DecodeModernCipherChoice(encoded, Profile.SelectCipher(decryptorId, this.modernLehLengthFirst), this.modernLehLengthFirst);
        }

        private byte[] DecodeModernCipherChoice(byte[] encoded, ModernCipherSelection selection, bool lengthFirst)
        {
            var data = (byte[])encoded.Clone();
            base.DecryptXor(data, this.KeyBuff);
            int decryptorId;
            decryptorId = selection.Id;
            if (selection.LegacyCipherId >= 0)
            {
                this.DecryptData(data, selection.LegacyCipherId, false);
                return data;
            }
			if (selection.SpecialRotatingXXTea)
			{
				
				if (data.Length % 8 != 0) throw new ArgumentException("Modern block cipher requires complete 8-byte blocks.");
				unchecked
				{
					uint delta = this.DataStructure.Encryption_Dword ^ 0x42689393U;
					for (int offset = 0; offset < data.Length; offset += 8)
					{
						uint a = BitConverter.ToUInt32(data, offset), b = BitConverter.ToUInt32(data, offset + 4);
						a ^= delta;
						uint sum = delta * 3U;
						int keyBase = (offset / 8) & 3;
						for (int round = 0; round < 3; round++)
						{
							int e = (int)(sum >> 2) & 3;
							uint keyB = BitConverter.ToUInt32(this.KeyBuff, ((keyBase + (e ^ 1)) & 3) * 4);
							b -= (((a << 4) ^ (a >> 3)) + ((a >> 5) ^ (a << 2))) ^ ((keyB ^ a) + (a ^ sum));
							uint keyA = BitConverter.ToUInt32(this.KeyBuff, ((keyBase + e) & 3) * 4);
							a -= (((b << 4) ^ (b >> 3)) + ((b >> 5) ^ (b << 2))) ^ ((keyA ^ b) + (b ^ sum));
							sum -= delta;
						}
						Buffer.BlockCopy(BitConverter.GetBytes(a), 0, data, offset, 4);
						Buffer.BlockCopy(BitConverter.GetBytes(b), 0, data, offset + 4, 4);
					}
				}
				return data;
			}
			if (selection.LegacyBlowfish)
			{

				this.DecryptData(data, 11, false);
			}
			else if (decryptorId == 1)
			{
				var state = new byte[256];
				var key = new byte[256];
				byte[] salt = BitConverter.GetBytes(this.DataStructure.Encryption_Dword);
				for (int i = 0; i < 256; i++)
				{
					state[i] = (byte)(salt[i & 3] ^ i);
					key[i] = (byte)(this.KeyBuff[i & 15] ^ (i >> 4));
				}
				int j = 0;
				for (int i = 0; i < 256; i++)
				{
					j = (j + state[i] + key[i]) & 255;
					byte temp = state[i]; state[i] = state[j]; state[j] = temp;
				}
				j = 0;
				for (int offset = 0; offset < data.Length; offset++)
				{
					int i = (offset + 1) & 255;
					j = (j + state[i]) & 255;
					byte temp = state[i]; state[i] = state[j]; state[j] = temp;
					data[offset] ^= state[(state[i] + state[j]) & 255];
				}
			}
			else if (decryptorId == 2)
			{
				base.DecryptPrevXor(data, this.KeyBuff);
				if (data.Length != 0) data[0] ^= this.KeyBuff[this.KeyBuff.Length - 1];
			}
			else if (selection.BlowfishMode >= 0)
            {
                int mode = selection.BlowfishMode;
				new Blowfish(this.KeyBuff, this.DataStructure.Encryption_Dword ^ this.DataStructure.ProtectionSettings).Process(data, data.Length, mode);
			}
			else if (decryptorId == 15) this.DecryptData(data, 15, false);
			else if (decryptorId == 5)
			{
				
				if (data.Length % 8 != 0) throw new ArgumentException("Modern block cipher requires complete 8-byte blocks.");
				unchecked
				{
					for (int offset = 0; offset < data.Length; offset += 8)
					{
						uint a = BitConverter.ToUInt32(data, offset), b = BitConverter.ToUInt32(data, offset + 4);
						uint sum = this.DataStructure.Encryption_Dword * 3U;
						for (int round = 0; round < 3; round++)
						{
							uint e = (sum >> 2) & 3U;
							uint y = (((a << 4) ^ (a >> 3)) + ((a >> 5) ^ (a << 2))) ^
								((BitConverter.ToUInt32(this.KeyBuff, (int)((e ^ 1U) * 4U)) ^ a) + (a ^ sum));
							b -= y;
							y = (((b << 4) ^ (b >> 3)) + ((b >> 5) ^ (b << 2))) ^
								((BitConverter.ToUInt32(this.KeyBuff, (int)(e * 4U)) ^ b) + (b ^ sum));
							a -= y;
							sum -= this.DataStructure.Encryption_Dword;
						}
						Buffer.BlockCopy(BitConverter.GetBytes(a), 0, data, offset, 4);
						Buffer.BlockCopy(BitConverter.GetBytes(b), 0, data, offset + 4, 4);
					}
				}
			}
			else if (decryptorId == 4 || (decryptorId == 8 && !lengthFirst) || decryptorId == 11 || (decryptorId == 10 && lengthFirst))
			{
				if (data.Length % 8 != 0) throw new ArgumentException("Modern block cipher requires complete 8-byte blocks.");
				unchecked
				{
					uint delta = this.DataStructure.Encryption_Dword;
					for (int offset = 0; offset < data.Length; offset += 8)
					{
						bool fourRounds = decryptorId == 11 || decryptorId == 10;
						int rounds = fourRounds ? 4 : 3;
						uint a = BitConverter.ToUInt32(data, offset), b = BitConverter.ToUInt32(data, offset + 4), sum = delta * (uint)rounds;
						if (fourRounds) b ^= delta;
						for (int round = 0; round < rounds; round++)
						{
							b -= (((a >> 5) ^ (a << 4)) + a) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)((sum >> 11) & 3) * 4) + sum);
							sum -= delta;
							a -= (((b >> 5) ^ (b << 4)) + b) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(sum & 3) * 4) + sum);
						}
						if (decryptorId == 4 || decryptorId == 8) a ^= delta;
						Buffer.BlockCopy(BitConverter.GetBytes(a), 0, data, offset, 4);
						Buffer.BlockCopy(BitConverter.GetBytes(b), 0, data, offset + 4, 4);
					}
				}
			}
			else if (decryptorId == 6 || (decryptorId == 8 && lengthFirst) ||
				(decryptorId == 9 && !lengthFirst) || selection.ForceRotatingXXTea)
			{
				if (data.Length % 8 != 0) throw new ArgumentException("Modern block cipher requires complete 8-byte blocks.");
				unchecked
				{
					uint delta = this.DataStructure.Encryption_Dword ^ 0x42689393U;
					int rounds = decryptorId == 9 || selection.ForceRotatingXXTea ? 3 : 2;
					for (int offset = 0; offset < data.Length; offset += 8)
					{
						uint a = BitConverter.ToUInt32(data, offset);
						uint b = BitConverter.ToUInt32(data, offset + 4);
						uint sum = delta * (uint)rounds;
						if (decryptorId == 9 || selection.ForceRotatingXXTea) a ^= delta;
						
						int keyBase = decryptorId == 9 || selection.ForceRotatingXXTea ? (offset / 8) & 3 : 0;
						for (int round = 0; round < rounds; round++)
						{
							int e = (int)(sum >> 2) & 3;
							uint keyB = BitConverter.ToUInt32(this.KeyBuff, ((keyBase + (e ^ 1)) & 3) * 4);
							b -= (((a << 4) ^ (a >> 3)) + ((a >> 5) ^ (a << 2))) ^ ((keyB ^ a) + (a ^ sum));
							uint keyA = BitConverter.ToUInt32(this.KeyBuff, ((keyBase + e) & 3) * 4);
							a -= (((b << 4) ^ (b >> 3)) + ((b >> 5) ^ (b << 2))) ^ ((keyA ^ b) + (b ^ sum));
							sum -= delta;
						}
						Buffer.BlockCopy(BitConverter.GetBytes(a), 0, data, offset, 4);
						Buffer.BlockCopy(BitConverter.GetBytes(b), 0, data, offset + 4, 4);
					}
				}
			}
			else if (decryptorId == 3 || decryptorId == 7 || decryptorId == 10 || (decryptorId == 9 && lengthFirst && !selection.ForceRotatingXXTea))
			{
				if (data.Length % 8 != 0) throw new ArgumentException("Modern block cipher requires complete 8-byte blocks.");
				unchecked
				{
					uint delta = this.DataStructure.Encryption_Dword ^ 0x42689393U;
					for (int offset = 0; offset < data.Length; offset += 8)
					{
						uint a = BitConverter.ToUInt32(data, offset);
						if (decryptorId == 9) a ^= this.DataStructure.Encryption_Dword;
						uint b = BitConverter.ToUInt32(data, offset + 4) ^ (decryptorId == 10 || decryptorId == 9 ? a : this.DataStructure.Encryption_Dword);
						if (decryptorId == 3) a ^= delta;
						int shift = decryptorId == 10 || decryptorId == 9 ? 5 : 3;
						uint sum = 5U * delta;
						for (int round = 0; round < 5; round++)
						{
							b -= BitConverter.ToUInt32(this.KeyBuff, (int)((sum >> 11) & 3) * 4) + ((a << shift) ^ (a >> 7)) + (a ^ sum);
							sum -= delta;
							a -= BitConverter.ToUInt32(this.KeyBuff, (int)(sum & 3) * 4) + ((b << shift) ^ (b >> 7)) + (b ^ sum);
						}
						Buffer.BlockCopy(BitConverter.GetBytes(a), 0, data, offset, 4);
						Buffer.BlockCopy(BitConverter.GetBytes(b), 0, data, offset + 4, 4);
					}
				}
			}
			else throw new NotSupportedException("Unverified modern cipher ID " + decryptorId);
			return data;
		}
    }
}
