using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.IO;
using dnlib.PE;

namespace DNGuard_Unpacker
{
    public partial class MethodsDecrypter
    {
		public class DecrypterBase : IDecrypter
		{
			
			public Dictionary<uint, uint> GetAnonymousTokens()
			{
				return this._anonymous_tokens;
			}

			protected DecrypterBase(ModuleDefMD module)
			{
				this.module = module;
				this.reader = module.Metadata.PEImage.CreateReader();
				this.methodInfos = new Dictionary<uint, MethodsDecrypter.DecrypterBase.methodInfo>();
				this.LocateDataStructure();
				this.MetaDataValue = this.ReadMetaDataStructure();
				bool flag = this.MetaDataValue == null;
				if (flag)
				{
					throw new InvalidDataException("未找到 DNGuard 元数据标记。");
				}
			}

			private void LocateDataStructure()
			{
				foreach (ImageSectionHeader imageSectionHeader in this.module.Metadata.PEImage.ImageSectionHeaders)
				{
					bool flag = this.DataSection != null;
					if (flag)
					{
						break;
					}
					this.DataOffset = imageSectionHeader.PointerToRawData;
					this.reader.Position = this.DataOffset;
					byte[] array = this.reader.ReadBytes((int)imageSectionHeader.SizeOfRawData);
					for (int i = 0; i <= array.Length - 10; i++)
					{
						bool flag2 = array[i] == 43 && array[i + 1] == 7 && (array[i + 2] == 115 || array[i + 2] == 32 || array[i + 2] == 40) && (array[i + 7] == 43 || array[i + 7] == 45) && array[i + 8] == 7 && (array[i + 9] == 114 || array[i + 9] == 32);
						if (flag2)
						{
							this.DataSection = imageSectionHeader;
							this.DataOffset += (uint)(i + 25);
							break;
						}
					}
				}
			}

			private uint[] ReadMetaDataStructure()
			{
				ImageDataDirectory imageDataDirectory = this.module.Metadata.PEImage.ImageNTHeaders.OptionalHeader.DataDirectories[14];
				DataReader dataReader = this.module.Metadata.PEImage.CreateReader(imageDataDirectory.VirtualAddress, 72U);
				ImageCor20Header imageCor20Header = new ImageCor20Header(ref dataReader, false);
				try
				{
					this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset(imageCor20Header.Metadata.VirtualAddress);
					bool flag = Encoding.UTF8.GetString(this.reader.ReadBytes(4)) == "BSJB";
					if (flag)
					{
						this.reader.Position = this.reader.Position - 20U;
						bool flag2 = Encoding.UTF8.GetString(this.reader.ReadBytes(4)) == "BSJB";
						if (flag2)
						{
							byte[] array = new byte[12];
							array = this.reader.ReadBytes(array.Length);
							uint[] array2 = new uint[array.Length / 4];
							Buffer.BlockCopy(array, 0, array2, 0, array.Length);
							return array2;
						}
					}
				}
				catch
				{
					return null;
				}
				return null;
			}

			public bool VerifyKeyBuffer(byte[] keybuffFull, uint encryption_dword)
			{
				Adler32 adler = new Adler32();
				adler.Update(keybuffFull);
				byte[] array = MD5.Create().ComputeHash(keybuffFull);
				long num = adler.Value >> 16;
				long num2 = adler.Value & 65535L;
				foreach (byte b in array)
				{
					num2 += (long)((ulong)b);
					num += num2;
				}
				num = (num & 65535L) + 15L;
				return encryption_dword == (uint)((num << 16) | num2);
			}

			protected virtual bool HvmTokenFormatEnabled => true;
            public virtual bool UsesEncodedMetadataTokens => IsHVMTechnologyEnabled();

			public bool IsHVMTechnologyEnabled()
			{
				return HvmTokenFormatEnabled && (this.DataStructure.ProtectionFeatures & MethodsDecrypter.DecrypterBase.ProtectSettings.HVMTechnology) == MethodsDecrypter.DecrypterBase.ProtectSettings.HVMTechnology;
			}

			public bool IsEnterpriseEdition()
			{
				return this.DataStructure.Encryption_Dword > 0U;
			}

			public bool IsCompatibilityModeEnabled()
			{
				return (this.DataStructure.ProtectionFeatures & MethodsDecrypter.DecrypterBase.ProtectSettings.CompatibilityMode) == MethodsDecrypter.DecrypterBase.ProtectSettings.CompatibilityMode;
			}

			public bool IsApplicationMode()
			{
				return (this.DataStructure.ProtectionFeatures & MethodsDecrypter.DecrypterBase.ProtectSettings.ApplicationMode) == MethodsDecrypter.DecrypterBase.ProtectSettings.ApplicationMode;
			}

			protected void DecryptXor(byte[] buff, byte[] key)
			{
				for (int i = 0; i < buff.Length; i++)
				{
					int num = i;
					buff[num] ^= key[i % key.Length];
				}
			}

			public byte[] DecryptPrevXor(byte[] buff, byte[] key)
			{
				byte b = 0;
				for (int i = 0; i < buff.Length; i++)
				{
					byte b2 = (byte)(buff[i] ^ key[i % key.Length] ^ b);
					b = buff[i];
					buff[i] = b2;
				}
				return buff;
			}

			public byte[] DecryptNextXor(byte[] buff, byte[] key)
			{
				byte b = buff[0];
				for (int i = 0; i < buff.Length - 1; i++)
				{
					byte b2 = (byte)(buff[i + 1] ^ key[i % key.Length] ^ b);
					b = buff[i + 1];
					buff[i + 1] = b2;
				}
				return buff;
			}

			public byte[] XorSelf(byte[] buff, int startoffset, int endoffset)
			{
				for (int num = endoffset - 1; num > startoffset; num--)
				{
					buff[num] ^= buff[num - 1];
				}
				buff[0] = (byte)(buff[endoffset - 1] ^ buff[0]);
				return buff;
			}

			private byte[] DecryptUS(USStream us_stream, uint length, byte[] encryption_key, uint encryption_dword_1, uint encryption_dword_2)
			{
				byte[] array = encryption_key;
				int num = 0;
				byte[] array2 = new byte[us_stream.StreamLength];
				DataReader dataReader = us_stream.CreateReader();
				dataReader.Position = 0U;
				dataReader.ReadBytes(array2, 0, (int)us_stream.StreamLength);
				dataReader.Position = 0U;
				Stream stream = new MemoryStream(array2);
				BinaryWriter binaryWriter = new BinaryWriter(stream);
				while ((ulong)dataReader.Position < (ulong)(length - 1U))
				{
					dataReader.Position += 1U;
					this.TransformEncryptionKey(ref array, encryption_dword_1 ^ dataReader.Position, encryption_dword_2);
					uint num2 = dataReader.ReadCompressedUInt32();
					binaryWriter.BaseStream.Position = (long)((ulong)dataReader.Position);
					byte[] array3 = new byte[num2 - 1U];
					dataReader.ReadBytes(array3, 0, array3.Length);
					num += array3.Length;
					for (int i = 0; i < array3.Length; i++)
					{
						byte[] array4 = array3;
						int num3 = i;
						array4[num3] ^= array[i % array.Length];
					}
					binaryWriter.Write(array3);
				}
				stream.Position = 0L;
				stream.Read(array2, 0, (int)us_stream.StreamLength);
				return array2;
			}

			private byte[] DecryptUSAtOffset(uint offset, uint length, byte[] encryption_key, uint encryption_dword_1, uint encryption_dword_2)
			{
				byte[] array = encryption_key;
				byte[] array2 = new byte[length];
				DataReader dataReader = this.module.Metadata.PEImage.CreateReader();
				dataReader.Position = offset;
				dataReader.ReadBytes(array2, 0, array2.Length);
				dataReader.Position = offset;
				DataReader dataReader2 = ByteArrayDataReaderFactory.CreateReader(array2);
				Stream stream = new MemoryStream(array2);
				BinaryWriter binaryWriter = new BinaryWriter(stream);
				uint num = 1U;
				while ((ulong)num < (ulong)length)
				{
					uint position = dataReader2.Position;
					uint num2 = dataReader2.ReadCompressedUInt32();
					uint position2 = dataReader2.Position;
					binaryWriter.BaseStream.Position = (long)((ulong)dataReader2.Position);
					this.TransformEncryptionKey(ref array, encryption_dword_1 ^ num, encryption_dword_2);
					if (num2 == 0U)
					{
						throw new Exception("num2 is too short");
					}
					byte[] array3 = new byte[num2 - 1U];
					dataReader2.ReadBytes(array3, 0, array3.Length);
					for (int i = 0; i < array3.Length; i++)
					{
						byte[] array4 = array3;
						int num3 = i;
						array4[num3] ^= array[i % array.Length];
					}
					dataReader2.Position += 1U;
					binaryWriter.Write(array3);
					num += num2 + position2 - position;
				}
				stream.Position = 0L;
				stream.Read(array2, 0, array2.Length);
				return array2;
			}

			public void TransformEncryptionKey(ref byte[] main_encryption_key, uint encryption_dword_1, uint encryption_dword_2)
			{
				uint[] array = new uint[main_encryption_key.Length / 4];
				Buffer.BlockCopy(main_encryption_key, 0, array, 0, main_encryption_key.Length);
				for (int i = 0; i < array.Length; i++)
				{
					array[i] ^= encryption_dword_2;
				}
				for (int j = 0; j < array.Length; j++)
				{
					array[j] ^= encryption_dword_1;
					main_encryption_key = new byte[array.Length * 4];
					Buffer.BlockCopy(array, 0, main_encryption_key, 0, main_encryption_key.Length);
				}
			}

			private void DecryptStrings(ref byte[] fileData)
			{
				byte[] encryption_key;
				if (this.DataStructure.KeyBuffOffset > 0U)
				{
					this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.KeyBuffOffset);
					encryption_key = this.reader.ReadBytes(16);
				}
				else
				{
					encryption_key = this.KeyBuff;
				}
				if (this.DataStructure.StringsOffset == 0U)
				{
					byte[] array = this.DecryptUS(this.module.USStream, this.DataStructure.EncryptedStringsSize, encryption_key, this.MetaDataValue[0], this.DataStructure.Encryption_Dword);
					Array.Copy(array, 0, fileData, (int)this.module.USStream.StartOffset, array.Length);
				}
				else
				{
					uint num = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.StringsOffset);
					byte[] array = this.DecryptUSAtOffset(num, this.DataStructure.EncryptedStringsSize, encryption_key, this.MetaDataValue[0], this.DataStructure.Encryption_Dword);
					Array.Copy(array, 0L, fileData, (long)((ulong)num), (long)array.Length);
				}
			}

			private void DecryptResources(ref byte[] fileData)
			{
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.ResourceStructureOffset);
				if ((ulong)this.reader.Position + (ulong)this.DataStructure.ResourceCount * 8 > (ulong)fileData.Length)
					throw new InvalidDataException("Encrypted resource table outside module.");
				int num = 0;
				while ((long)num < (long)((ulong)this.DataStructure.ResourceCount))
				{
					uint num2 = this.reader.ReadUInt32();
					uint num3 = (this.reader.ReadUInt32() ^ num2 ^ this.DataStructure.Encryption_Dword) & 2147483647U;
					uint raw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)num2);
					if ((uint)this.module.Metadata.PEImage.ToRVA((FileOffset)raw) != num2 || (ulong)raw + 4 + num3 > (ulong)fileData.Length)
						throw new InvalidDataException("Encrypted resource payload outside module.");
					Array.Copy(BitConverter.GetBytes(num3), 0L, fileData, (long)((ulong)this.module.Metadata.PEImage.ToFileOffset((RVA)num2)), 4L);
					bool flag = this.IsHVMTechnologyEnabled();
					if (flag)
					{
						uint position = this.reader.Position;
						this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset(num2 + (RVA)4U);
						byte[] array = this.reader.ReadBytes((int)num3);
						this.DecryptPrevXor(array, this.KeyBuff);
						Array.Copy(array, 0L, fileData, (long)((ulong)this.module.Metadata.PEImage.ToFileOffset(num2 + (RVA)4U)), (long)((ulong)num3));
						this.reader.Position = position;
					}
					num++;
				}
			}

            public virtual string ReadInlineUserString(uint token)
            {
                return this.module.ReadUserString(token);
            }
			public virtual string ReadUserStringFromOffset(uint token)
			{
				try
				{
					uint num;
					if (this.DataStructure.StringsOffset == 0U)
					{
						if (this.module.USStream != null)
						{
							num = (uint)this.module.USStream.StartOffset;
						}
						else
						{
							return null;
						}
					}
					else
					{
						num = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.StringsOffset);
					}
					this.reader.Position = num + token - 1U;
					uint num2 = this.reader.ReadCompressedUInt32();
					if (num2 == 0U || num2 > 1000000U)
					{
						return null;
					}
					byte[] array = new byte[num2 - 1U];
					this.reader.ReadBytes(array, 0, array.Length);
					return Encoding.Unicode.GetString(array);
				}
				catch
				{
					return null;
				}
			}

			public virtual void DecryptInternal(ref byte[] fileData)
			{
				if (this.DataStructure.EncryptedStringsSize > 0U)
				{
					this.DecryptStrings(ref fileData);
				}
				if (this.DataStructure.ResourceCount > 0U)
				{
					this.DecryptResources(ref fileData);
				}
			}

			public virtual void ParseStructure()
			{
			}

			public virtual void ReadMethods()
			{
			}

			public virtual uint DecryptHVMToken(uint hvmToken, int hvmCounter, MethodsDecrypter.DecrypterBase.methodInfo mi)
			{
				return 0U;
			}

            protected virtual bool PreserveMethodImplAttributes { get { return false; } }
			public void RestoreMethods()
			{
				if (this.methodInfos.Count > 0)
				{
					Console.ForegroundColor = ConsoleColor.Yellow;
					Console.WriteLine(string.Format("- Restoring {0} methods", this.methodInfos.Count));
					foreach (TypeDef typeDef in this.module.GetTypes())
					{
						foreach (MethodDef methodDef in typeDef.Methods)
						{
							try
							{
								if (methodDef.HasBody)
								{
									if (this.RestoreMethod(methodDef))
									{
										MethodDef methodDef2 = methodDef;
									if (!this.PreserveMethodImplAttributes) methodDef2.ImplAttributes &= ~MethodImplAttributes.NoInlining;
										int len = 10;
										string name = methodDef.Name.Replace('\n', ' ').Replace('\r', ' ');
										if (name.Length > len)
										{
											name = name.Substring(0, len);
										}
										Console.ForegroundColor = ConsoleColor.Cyan;
										if (ConsoleLog.Verbose || ConsoleLog.Legacy) Console.WriteLine("- Restored method {0} ({1:X8})\r\n  Instrs: {2}\r\n  Locals: {3}\r\n  Exceptions: {4}", new object[]
										{
											name,
											methodDef.MDToken,
											methodDef.Body.Instructions.Count,
											methodDef.Body.Variables.Count,
											methodDef.Body.ExceptionHandlers.Count
										});
									}
								}
							}
							catch (Exception error)
							{
								throw new InvalidDataException("Failed to restore method " + methodDef.MDToken + " " + methodDef.FullName, error);
							}
						}
					}
					bool flag4 = this.methodInfos.Count != 0;
					if (flag4)
					{
						Console.ForegroundColor = ConsoleColor.Red;
						Console.WriteLine("- {0} methods weren't restored", new object[] { this.methodInfos.Count });
					}
				}
			}

			private bool RestoreMethod(MethodDef method)
			{
				uint rid = method.Rid;
				bool flag = !this.methodInfos.ContainsKey(rid);
				bool result;
				if (flag)
				{
					result = false;
				}
				else
				{
					ParameterList parameters = method.Parameters;
					MethodsDecrypter.DecrypterBase.methodInfo mi = this.methodInfos[rid];
					MethodReader methodReader = new MethodReader(this.module, mi, parameters, this);
					methodReader.Read(method);
					methodReader.RestoreMethod(method);
					this.methodInfos.Remove(rid);
					result = true;
				}
				return result;
			}

			protected ModuleDefMD module;

			protected DataReader reader;

			protected readonly Dictionary<uint, MethodsDecrypter.DecrypterBase.methodInfo> methodInfos;

			protected Dictionary<uint, uint> proxyMethods = new Dictionary<uint, uint>();

			protected List<int> fakeMethods = new List<int>();

			protected List<int> secureMethods = new List<int>();

			protected Dictionary<uint, uint> _anonymous_tokens = new Dictionary<uint, uint>();

			protected ImageSectionHeader DataSection;

			protected uint DataOffset;

			protected MethodsDecrypter.DecrypterBase.DataStruct DataStructure;

			protected uint[] MetaDataValue;

			protected byte[] KeyBuff = new byte[]
			{
				139, 248, 59, 251, 15, 132, 191, 25, 40, 0,
				199, 69, 232, 1, 0, 0
			};

			protected struct DataStruct
			{
				
				public uint Encryption_Dword;

				public uint MethodsBufferLength;

				public uint MethodsDataOffset;

				public uint KeyBuffOffset;

				public uint MethodsCount;

				public uint StringsOffset;

				public uint EncryptedStringsSize;

				public uint LocalsAndEHOffset;

				public uint LEHSize;

				public uint ResourceStructureOffset;

				public uint ResourceCount;

				public uint ProtectionSettings;

				public MethodsDecrypter.DecrypterBase.ProtectSettings ProtectionFeatures;

				public byte[] _MethodsOffsetTable;

				public byte[] LEH;

				public byte[] _MethodsData;
			}

			public struct methodInfo
			{
				
				public byte DecryptorType;

				public uint MethodDataOffset;

				public MDToken MDToken;

				public byte[] Header;

				public byte[] MethodData;

				public List<Local> Method_Locals;

				public byte[] MethodEH;

				public uint HvmTokenTableOffset;

				public uint HvmTokenTableSize;

				public uint[] MethodHvmTokens;

                public int[] ModernTokenIndices;

				public MethodDef Method;
			}

			[Flags]
			protected enum ProtectSettings
			{
				
				Default = 512,
				
				MorePerformanceButLessSecurity = 1,
				
				HVMTechnology = 2,
				
				HVMEHTable = 32,
				
				HVMLocalVarSigTok = 64,
				
				HVMStrings = 128,
				
				HVMIllegalAction = 256,
				
				ApplicationMode = 1024,
				
				CompatibilityMode = 2048
			}
		}
    }
}
