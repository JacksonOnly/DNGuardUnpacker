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
		private void DecryptData2(byte[] data, int decryptorId, bool hvm_xor)
		{
			if (decryptorId == 0)
			{
				bool flag2 = base.IsHVMTechnologyEnabled() && hvm_xor;
				if (flag2)
				{
					base.DecryptNextXor(data, this.KeyBuff);
				}
				base.DecryptXor(data, this.KeyBuff);
			}
			else if (decryptorId == 1)
			{
				bool flag3 = base.IsHVMTechnologyEnabled() && hvm_xor;
				if (flag3)
				{
					base.DecryptNextXor(data, this.KeyBuff);
				}
				byte prev = this.KeyBuff[this.KeyBuff.Length - 1];
				for (int i = 0; i < data.Length; i++)
				{
					byte next = (byte)(data[i] ^ this.KeyBuff[i % this.KeyBuff.Length] ^ prev);
					prev = data[i];
					data[i] = next;
				}
			}
			else if (decryptorId == 8)
			{
				bool flag4 = base.IsHVMTechnologyEnabled() && hvm_xor;
				if (flag4)
				{
					base.DecryptNextXor(data, this.KeyBuff);
				}
				int buff_counter = 0;
				int buff_index = 0;
				bool flag5 = data.Length >> 3 > 0;
				if (flag5)
				{
					uint[] buff = new uint[data.Length / 4];
					Buffer.BlockCopy(data, 0, buff, 0, data.Length);
					while (buff_counter < data.Length >> 3)
					{
						uint uVar7 = this.DataStructure.Encryption_Dword * 8U;
						int cnt = 7;
						uint uVar8 = buff[buff_index];
						uint uVar9 = buff[buff_index + 1] - ((((uVar8 >> 5) ^ (uVar8 << 4)) + uVar8) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((uVar7 >> 11) & 3U) * 4U)) + uVar7));
						uVar7 -= this.DataStructure.Encryption_Dword;
						while (cnt != 0)
						{
							uVar8 -= (((uVar9 >> 5) ^ (uVar9 * 16U)) + uVar9) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)((uVar7 & 3U) * 4U)) + uVar7);
							uVar9 -= (((uVar8 >> 5) ^ (uVar8 * 16U)) + uVar8) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((uVar7 >> 11) & 3U) * 4U)) + uVar7);
							uVar7 -= this.DataStructure.Encryption_Dword;
							cnt--;
						}
						buff[buff_index] = (uVar8 - ((((uVar9 >> 5) ^ (uVar9 * 16U)) + uVar9) ^ BitConverter.ToUInt32(this.KeyBuff, (int)((uVar7 & 3U) * 4U)))) ^ this.DataStructure.Encryption_Dword;
						buff[buff_index + 1] = uVar9;
						buff_counter++;
						buff_index += 2;
					}
					Buffer.BlockCopy(buff, 0, data, 0, data.Length);
				}
			}
			else
			{
				bool flag6 = decryptorId == 6;
				if (flag6)
				{
					bool flag7 = base.IsHVMTechnologyEnabled() && hvm_xor;
					if (flag7)
					{
						base.DecryptNextXor(data, this.KeyBuff);
					}
					int buff_counter2 = 0;
					int buff_index2 = 0;
					bool flag8 = data.Length >> 3 > 0;
					if (flag8)
					{
						uint[] buff2 = new uint[data.Length / 4];
						Buffer.BlockCopy(data, 0, buff2, 0, data.Length);
						while (buff_counter2 < data.Length >> 3)
						{
							uint uVar10 = this.DataStructure.Encryption_Dword * 6U;
							for (int cnt2 = 6; cnt2 != 0; cnt2--)
							{
								uint uVar11 = (uVar10 >> 2) & 3U;
								uint uVar12 = buff2[buff_index2];
								uint y = (((uVar12 << 4) ^ (uVar12 >> 3)) + ((uVar12 >> 5) ^ (uVar12 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)((uVar11 ^ 1U) * 4U)) ^ uVar12) + (uVar12 ^ uVar10));
								buff2[buff_index2 + 1] = buff2[buff_index2 + 1] - y;
								uVar12 = buff2[buff_index2 + 1];
								y = (((uVar12 << 4) ^ (uVar12 >> 3)) + ((uVar12 >> 5) ^ (uVar12 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(uVar11 * 4U)) ^ uVar12) + (uVar12 ^ uVar10));
								buff2[buff_index2] -= y;
								uVar10 -= this.DataStructure.Encryption_Dword;
							}
							buff_counter2++;
							buff_index2 += 2;
						}
						Buffer.BlockCopy(buff2, 0, data, 0, data.Length);
					}
				}
				else
				{
					bool flag9 = decryptorId == 10;
					if (flag9)
					{
						bool flag10 = base.IsHVMTechnologyEnabled() && hvm_xor;
						if (flag10)
						{
							base.DecryptNextXor(data, this.KeyBuff);
						}
						int buff_counter3 = 0;
						int buff_index3 = 0;
						bool flag11 = data.Length >> 3 > 0;
						if (flag11)
						{
							uint[] buff3 = new uint[data.Length / 4];
							Buffer.BlockCopy(data, 0, buff3, 0, data.Length);
							while (buff_counter3 < data.Length >> 3)
							{
								buff3[buff_index3] ^= this.DataStructure.Encryption_Dword;
								uint uVar13 = this.DataStructure.Encryption_Dword * 8U;
								for (int cnt3 = 8; cnt3 != 0; cnt3--)
								{
									uint uVar14 = (uVar13 >> 2) & 3U;
									uint uVar15 = buff3[buff_index3];
									uint y2 = (((uVar15 << 4) ^ (uVar15 >> 3)) + ((uVar15 >> 5) ^ (uVar15 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(((ulong)(uVar14 ^ 1U) + (ulong)((long)buff_counter3)) * 4UL % (ulong)((long)this.KeyBuff.Length))) ^ uVar15) + (uVar15 ^ uVar13));
									buff3[buff_index3 + 1] = buff3[buff_index3 + 1] - y2;
									uVar15 = buff3[buff_index3 + 1];
									y2 = (((uVar15 << 4) ^ (uVar15 >> 3)) + ((uVar15 >> 5) ^ (uVar15 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(((ulong)uVar14 + (ulong)((long)buff_counter3)) * 4UL) % this.KeyBuff.Length) ^ uVar15) + (uVar15 ^ uVar13));
									buff3[buff_index3] -= y2;
									uVar13 -= this.DataStructure.Encryption_Dword;
								}
								buff_counter3++;
								buff_index3 += 2;
							}
							Buffer.BlockCopy(buff3, 0, data, 0, data.Length);
						}
					}
					else
					{
						bool flag12 = decryptorId == 14;
						if (flag12)
						{
							bool flag13 = base.IsHVMTechnologyEnabled() && hvm_xor;
							if (flag13)
							{
								base.DecryptNextXor(data, this.KeyBuff);
							}
							int buff_counter4 = 0;
							int buff_index4 = 0;
							bool flag14 = data.Length >> 3 > 0;
							if (flag14)
							{
								uint[] buff4 = new uint[data.Length / 4];
								Buffer.BlockCopy(data, 0, buff4, 0, data.Length);
								while (buff_counter4 < data.Length >> 3)
								{
									uint uVar16 = this.DataStructure.Encryption_Dword * 9U;
									int cnt4 = 8;
									uint uVar17 = buff4[buff_index4];
									uint uVar18 = (buff4[buff_index4 + 1] ^ this.DataStructure.Encryption_Dword) - ((((uVar17 >> 5) ^ (uVar17 << 4)) + uVar17) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((uVar16 >> 11) & 3U) * 4U)) + uVar16));
									uVar16 -= this.DataStructure.Encryption_Dword;
									while (cnt4 != 0)
									{
										uVar17 -= (((uVar18 >> 5) ^ (uVar18 * 16U)) + uVar18) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)((uVar16 & 3U) * 4U)) + uVar16);
										uVar18 -= (((uVar17 >> 5) ^ (uVar17 * 16U)) + uVar17) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((uVar16 >> 11) & 3U) * 4U)) + uVar16);
										uVar16 -= this.DataStructure.Encryption_Dword;
										cnt4--;
									}
									buff4[buff_index4] = uVar17 - ((((uVar18 >> 5) ^ (uVar18 * 16U)) + uVar18) ^ BitConverter.ToUInt32(this.KeyBuff, (int)((uVar16 & 3U) * 4U)));
									buff4[buff_index4 + 1] = uVar18;
									buff_counter4++;
									buff_index4 += 2;
								}
								Buffer.BlockCopy(buff4, 0, data, 0, data.Length);
							}
						}
						else
						{
							bool flag15 = decryptorId == 2;
							if (flag15)
							{
								bool flag16 = base.IsHVMTechnologyEnabled() && hvm_xor;
								if (flag16)
								{
									base.DecryptNextXor(data, this.KeyBuff);
								}
								byte[] blob = new byte[256];
								int uVar19 = 0;
								int index = 0;
								for (int j = 0; j < blob.Length; j++)
								{
									if (j % 4 == 0)
									{
										index = 0;
									}
									blob[j] = (byte)((int)BitConverter.GetBytes(this.DataStructure.Encryption_Dword)[index] ^ uVar19);
									uVar19++;
									index++;
								}
								byte[] blob2 = new byte[256];
								uVar19 = 0;
								index = 0;
								for (int k = 0; k < blob2.Length; k++)
								{
									if (k % 16 == 0)
									{
										index = 0;
									}
									blob2[k] = (byte)(this.KeyBuff[index] ^ (byte)(uVar19 >> 4));
									byte[] array = blob;
									int num = k;
									byte[] array2 = array;
									int num3 = num;
									array2[num3] ^= blob2[k];
									uVar19++;
									index++;
								}
								int tmp = 0;
								for (int l = 0; l < blob.Length; l++)
								{
									tmp = tmp + (int)blob[l] + (int)blob2[l];
									byte tmp2 = blob[l];
									blob[l] = blob[tmp & 255];
									blob[tmp & 255] = tmp2;
								}
								int start = 1;
								tmp = 0;
								for (int m = 0; m < data.Length; m++)
								{
									byte tmp3 = blob[start & 255];
									tmp = (tmp + (int)tmp3) & 255;
									byte tmp4 = blob[tmp];
									blob[start & 255] = tmp4;
									blob[tmp] = tmp3;
									int num2 = m;
									int num4 = num2;
									data[num4] ^= blob[(int)((tmp3 + tmp4) & byte.MaxValue)];
									start++;
								}
							}
							else
							{
								bool flag17 = decryptorId == 12;
								if (flag17)
								{
									bool flag18 = base.IsHVMTechnologyEnabled() && hvm_xor;
									if (flag18)
									{
										base.DecryptNextXor(data, this.KeyBuff);
									}
									bool flag19 = data.Length >> 3 > 0;
									if (flag19)
									{
										uint w = this.DataStructure.Encryption_Dword ^ 2656670661U;
										uint enc_w = 8U * w;
										uint init_w = enc_w;
										uint[] buff5 = new uint[data.Length / 4];
										Buffer.BlockCopy(data, 0, buff5, 0, data.Length);
										for (int n = 0; n < buff5.Length; n += 2)
										{
											uint dw2 = buff5[n] ^ this.DataStructure.Encryption_Dword;
											uint dw3 = buff5[n + 1] ^ dw2;
											while (enc_w > 0U)
											{
												dw3 -= BitConverter.ToUInt32(this.KeyBuff, (int)(((enc_w >> 11) & 3U) * 4U)) + ((dw2 << 5) ^ (dw2 >> 7)) + (dw2 ^ enc_w);
												enc_w -= w;
												dw2 -= BitConverter.ToUInt32(this.KeyBuff, (int)((enc_w & 3U) * 4U)) + ((32U * dw3) ^ (dw3 >> 7)) + (dw3 ^ enc_w);
											}
											enc_w = init_w;
											buff5[n] = dw2;
											buff5[n + 1] = dw3;
										}
										Buffer.BlockCopy(buff5, 0, data, 0, data.Length);
									}
								}
								else
								{
									bool flag20 = decryptorId == 4;
									if (flag20)
									{
										bool flag21 = base.IsHVMTechnologyEnabled() && hvm_xor;
										if (flag21)
										{
											base.DecryptNextXor(data, this.KeyBuff);
										}
										bool flag22 = data.Length >> 3 > 0;
										if (flag22)
										{
											uint w2 = this.DataStructure.Encryption_Dword ^ 2656670661U;
											uint enc_w2 = 8U * w2;
											uint init_w2 = enc_w2;
											uint[] buff6 = new uint[data.Length / 4];
											Buffer.BlockCopy(data, 0, buff6, 0, data.Length);
											for (int j2 = 0; j2 < buff6.Length; j2 += 2)
											{
												uint dw4 = buff6[j2 + 1];
												uint dw5 = buff6[j2] ^ dw4;
												while (enc_w2 > 0U)
												{
													dw4 -= BitConverter.ToUInt32(this.KeyBuff, (int)(((enc_w2 >> 11) & 3U) * 4U)) + ((8U * dw5) ^ (dw5 >> 7)) + (dw5 ^ enc_w2);
													enc_w2 -= w2;
													dw5 -= BitConverter.ToUInt32(this.KeyBuff, (int)((enc_w2 & 3U) * 4U)) + ((8U * dw4) ^ (dw4 >> 7)) + (dw4 ^ enc_w2);
												}
												enc_w2 = init_w2;
												buff6[j2] = dw5;
												buff6[j2 + 1] = dw4;
											}
											Buffer.BlockCopy(buff6, 0, data, 0, data.Length);
										}
									}
									else
									{
										bool flag23 = decryptorId == 11;
										if (flag23)
										{
											bool flag24 = base.IsHVMTechnologyEnabled() && hvm_xor;
											if (flag24)
											{
												base.DecryptNextXor(data, this.KeyBuff);
											}
											int type = 2;
											new Blowfish(this.KeyBuff, this.DataStructure.Encryption_Dword).Process(data, data.Length, type);
										}
										else
										{
											bool flag25 = decryptorId == 9;
											if (flag25)
											{
												bool flag26 = base.IsHVMTechnologyEnabled() && hvm_xor;
												if (flag26)
												{
													base.DecryptNextXor(data, this.KeyBuff);
												}
												int type2 = 1;
												new Blowfish(this.KeyBuff, this.DataStructure.Encryption_Dword).Process(data, data.Length, type2);
											}
											else
											{
												if (decryptorId != 13)
												{
													throw new NotImplementedException();
												}
												bool flag27 = base.IsHVMTechnologyEnabled() && hvm_xor;
												if (flag27)
												{
													base.DecryptNextXor(data, this.KeyBuff);
												}
												int type3 = 0;
												new Blowfish(this.KeyBuff, this.DataStructure.Encryption_Dword).Process(data, data.Length, type3);
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		private void DecryptData(byte[] data, int decryptorId, bool hvm_xor)
		{
			switch (decryptorId)
			{
			case 0:
				base.DecryptXor(data, this.KeyBuff);
				return;
			case 1:
			{
				byte b3 = this.KeyBuff[this.KeyBuff.Length - 1];
				for (int i = 0; i < data.Length; i++)
				{
					byte b4 = (byte)(data[i] ^ this.KeyBuff[i % this.KeyBuff.Length] ^ b3);
					b3 = data[i];
					data[i] = b4;
				}
				return;
			}
			case 2:
			{
				byte[] array8 = new byte[256];
				int num39 = 0;
				int num40 = 0;
				for (int j = 0; j < array8.Length; j++)
				{
					if (j % 4 == 0)
					{
						num40 = 0;
					}
					array8[j] = (byte)((int)BitConverter.GetBytes(this.DataStructure.Encryption_Dword)[num40] ^ num39);
					num39++;
					num40++;
				}
				byte[] array9 = new byte[256];
				num39 = 0;
				num40 = 0;
				for (int k = 0; k < array9.Length; k++)
				{
					if (k % 16 == 0)
					{
						num40 = 0;
					}
					array9[k] = this.KeyBuff[num40];
					byte[] array17 = array8;
					int num83 = k;
					array17[num83] ^= array9[k];
					num39++;
					num40++;
				}
				int num41 = 0;
				for (int num42 = 0; num42 < array8.Length; num42++)
				{
					num41 = num41 + (int)array8[num42] + (int)array9[num42];
					byte b5 = array8[num42];
					array8[num42] = array8[num41 & 255];
					array8[num41 & 255] = b5;
				}
				int num43 = 1;
				num41 = 0;
				for (int num44 = 0; num44 < data.Length; num44++)
				{
					byte b6 = array8[num43 & 255];
					num41 = (num41 + (int)b6) & 255;
					byte b7 = (array8[num43 & 255] = array8[num41]);
					array8[num41] = b6;
					int num84 = num44;
					data[num84] ^= array8[(int)((b6 + b7) & byte.MaxValue)];
					num43++;
				}
				return;
			}
			case 4:
			{
				int num45 = 0;
				int num46 = 0;
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint[] array10 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array10, 0, data.Length);
				while (num45 < data.Length >> 3)
				{
					uint num47 = this.DataStructure.Encryption_Dword * 4U;
					int num48 = 3;
					uint num49 = array10[num46];
					uint num50 = array10[num46 + 1] - ((((num49 >> 5) ^ (num49 << 4)) + num49) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((num47 >> 11) & 3U) * 4U)) + num47));
					num47 -= this.DataStructure.Encryption_Dword;
					while (num48 != 0)
					{
						num49 -= (((num50 >> 5) ^ (num50 * 16U)) + num50) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)((num47 & 3U) * 4U)) + num47);
						num50 -= (((num49 >> 5) ^ (num49 * 16U)) + num49) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((num47 >> 11) & 3U) * 4U)) + num47);
						num47 -= this.DataStructure.Encryption_Dword;
						num48--;
					}
					array10[num46] = num49 - ((((num50 >> 5) ^ (num50 * 16U)) + num50) ^ BitConverter.ToUInt32(this.KeyBuff, (int)((num47 & 3U) * 4U)));
					array10[num46 + 1] = num50 ^ this.DataStructure.Encryption_Dword;
					num45++;
					num46 += 2;
				}
				Buffer.BlockCopy(array10, 0, data, 0, data.Length);
				return;
			}
			case 5:
			{
				int num51 = 0;
				int num52 = 0;
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint[] array11 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array11, 0, data.Length);
				while (num51 < data.Length >> 3)
				{
					uint num53 = this.DataStructure.Encryption_Dword * 3U;
					for (int num54 = 3; num54 != 0; num54--)
					{
						uint num55 = (num53 >> 2) & 3U;
						uint num56 = array11[num52];
						uint num57 = (((num56 << 4) ^ (num56 >> 3)) + ((num56 >> 5) ^ (num56 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)((num55 ^ 1U) * 4U)) ^ num56) + (num56 ^ num53));
						array11[num52 + 1] = array11[num52 + 1] - num57;
						num56 = array11[num52 + 1];
						num57 = (((num56 << 4) ^ (num56 >> 3)) + ((num56 >> 5) ^ (num56 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(num55 * 4U)) ^ num56) + (num56 ^ num53));
						array11[num52] -= num57;
						num53 -= this.DataStructure.Encryption_Dword;
					}
					num51++;
					num52 += 2;
				}
				Buffer.BlockCopy(array11, 0, data, 0, data.Length);
				return;
			}
			case 6:
			{
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint num58 = this.DataStructure.Encryption_Dword ^ 2656670661U;
				uint num59 = 8U * num58;
				uint num60 = num59;
				uint[] array12 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array12, 0, data.Length);
				for (int l = 0; l < array12.Length; l += 2)
				{
					uint num61 = array12[l];
					uint num62 = array12[l + 1] ^ num61;
					while (num59 != 0U)
					{
						num62 -= BitConverter.ToUInt32(this.KeyBuff, (int)(((num59 >> 11) & 3U) * 4U)) + ((8U * num61) ^ (num61 >> 7)) + (num61 ^ num59);
						num59 -= num58;
						num61 -= BitConverter.ToUInt32(this.KeyBuff, (int)((num59 & 3U) * 4U)) + ((8U * num62) ^ (num62 >> 7)) + (num62 ^ num59);
					}
					num59 = num60;
					array12[l] = num61;
					array12[l + 1] = num62;
				}
				Buffer.BlockCopy(array12, 0, data, 0, data.Length);
				return;
			}
			case 9:
			{
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint num63 = this.DataStructure.Encryption_Dword ^ 2656670661U;
				uint num64 = 8U * num63;
				uint num65 = num64;
				uint[] array13 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array13, 0, data.Length);
				for (int m = 0; m < array13.Length; m += 2)
				{
					uint num66 = array13[m] ^ this.DataStructure.Encryption_Dword;
					uint num67 = array13[m + 1];
					while (num64 != 0U)
					{
						num67 -= BitConverter.ToUInt32(this.KeyBuff, (int)(((num64 >> 11) & 3U) * 4U)) + ((num66 << 5) ^ (num66 >> 7)) + (num66 ^ num64);
						num64 -= num63;
						num66 -= BitConverter.ToUInt32(this.KeyBuff, (int)((num64 & 3U) * 4U)) + ((32U * num67) ^ (num67 >> 7)) + (num67 ^ num64);
					}
					num64 = num65;
					array13[m] = num66;
					array13[m + 1] = num67;
				}
				Buffer.BlockCopy(array13, 0, data, 0, data.Length);
				return;
			}
			case 10:
			{
				int type3 = 2;
				this.blowfishInstance.Process(data, data.Length, type3);
				return;
			}
			case 11:
			{
				int type4 = 0;
				this.blowfishInstance.Process(data, data.Length, type4);
				return;
			}
			case 12:
			{
				int type5 = 1;
				this.blowfishInstance.Process(data, data.Length, type5);
				return;
			}
			case 13:
			{
				int num68 = 0;
				int num69 = 0;
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint[] array14 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array14, 0, data.Length);
				while (num68 < data.Length >> 3)
				{
					uint num70 = this.DataStructure.Encryption_Dword * 6U;
					int num71 = 5;
					uint num72 = array14[num69] ^ array14[num69 + 1];
					uint num73 = array14[num69 + 1] - ((((num72 >> 5) ^ (num72 << 4)) + num72) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((num70 >> 11) & 3U) * 4U)) + num70));
					num70 -= this.DataStructure.Encryption_Dword;
					while (num71 != 0)
					{
						num72 -= (((num73 >> 5) ^ (num73 * 16U)) + num73) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)((num70 & 3U) * 4U)) + num70);
						num73 -= (((num72 >> 5) ^ (num72 * 16U)) + num72) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((num70 >> 11) & 3U) * 4U)) + num70);
						num70 -= this.DataStructure.Encryption_Dword;
						num71--;
					}
					array14[num69] = num72 - ((((num73 >> 5) ^ (num73 * 16U)) + num73) ^ BitConverter.ToUInt32(this.KeyBuff, (int)((num70 & 3U) * 4U)));
					array14[num69 + 1] = num73;
					num68++;
					num69 += 2;
				}
				Buffer.BlockCopy(array14, 0, data, 0, data.Length);
				return;
			}
			case 14:
			{
				int num74 = 0;
				int num75 = 0;
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint[] array15 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array15, 0, data.Length);
				while (num74 < data.Length >> 3)
				{
					array15[num75] ^= this.DataStructure.Encryption_Dword;
					uint num76 = this.DataStructure.Encryption_Dword * 6U;
					for (int num77 = 6; num77 != 0; num77--)
					{
						uint num78 = (num76 >> 2) & 3U;
						uint num79 = array15[num75];
						uint num80 = (((num79 << 4) ^ (num79 >> 3)) + ((num79 >> 5) ^ (num79 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(((ulong)(num78 ^ 1U) + (ulong)((long)num74)) * 4UL % (ulong)((long)this.KeyBuff.Length))) ^ num79) + (num79 ^ num76));
						array15[num75 + 1] = array15[num75 + 1] - num80;
						num79 = array15[num75 + 1];
						num80 = (((num79 << 4) ^ (num79 >> 3)) + ((num79 >> 5) ^ (num79 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(((ulong)num78 + (ulong)((long)num74)) * 4UL) % this.KeyBuff.Length) ^ num79) + (num79 ^ num76));
						array15[num75] -= num80;
						num76 -= this.DataStructure.Encryption_Dword;
					}
					num74++;
					num75 += 2;
				}
				Buffer.BlockCopy(array15, 0, data, 0, data.Length);
				return;
			}
			case 15:
			{
				byte[] array16 = new byte[256];
				Buffer.BlockCopy(this.algoKey, 0, array16, 0, this.algoKey.Length);
				int num81 = 0;
				int num82 = 0;
				for (int n = 0; n < data.Length; n++)
				{
					num81++;
					byte b8 = array16[num81 & 255];
					num82 = (num82 + (int)b8) & 255;
					byte b9 = (array16[num81 & 255] = array16[num82 & 255]);
					array16[num82 & 255] = b8;
					data[n] ^= array16[(int)((b9 + b8) & byte.MaxValue)];
				}
				return;
			}
			}
			throw new NotImplementedException();
		}
    }
}
