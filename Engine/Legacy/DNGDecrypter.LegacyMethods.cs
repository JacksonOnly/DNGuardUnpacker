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
		public override void ReadMethods()
		{
			if (this.modernLayout) { this.ReadModernMethods(); return; }
            if (base.IsApplicationMode() && this.externalMethods == null)
			{
                throw new InvalidDataException("应用模式的方法块位于容器中；请使用原始 Single EXE，或通过 --container 指定原始容器。");
			}
			this.ValidateMethodDataBounds();
            if (this.externalMethods != null)
            {
                var block = ByteArrayDataReaderFactory.CreateReader(this.externalMethods);
                this.DataStructure._MethodsOffsetTable = block.ReadBytes(checked((int)this.DataStructure.MethodsCount * 4));
                this.DataStructure._MethodsData = block.ReadBytes(checked((int)this.DataStructure.MethodsBufferLength));
                this.DataStructure.LEH = block.ReadBytes(checked((int)this.DataStructure.LEHSize));
            }
            else if (this.ContiguousLegacyLeh)
			{
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.MethodsDataOffset);
				this.DataStructure._MethodsOffsetTable = this.reader.ReadBytes((int)(this.DataStructure.MethodsCount * 4U));
				this.DataStructure._MethodsData = this.reader.ReadBytes((int)this.DataStructure.MethodsBufferLength);
				uint rva = (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)this.reader.Position);
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = this.reader.ReadBytes((int)this.DataStructure.LEHSize);
				}
			}
			else
			{
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.LocalsAndEHOffset);
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = this.reader.ReadBytes((int)this.DataStructure.LEHSize);
				}
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.MethodsDataOffset);
				this.DataStructure._MethodsOffsetTable = this.reader.ReadBytes((int)(this.DataStructure.MethodsCount * 4U));
				this.DataStructure._MethodsData = this.reader.ReadBytes((int)this.DataStructure.MethodsBufferLength);
			}
			if (base.IsEnterpriseEdition())
			{
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = EarlyInlineLayout ? FixedWidthLzw.Decode(this.DataStructure.LEH) : new LZAri().Decode(this.DataStructure.LEH);
					base.DecryptPrevXor(this.DataStructure.LEH, this.KeyBuff);
				}
				this.DataStructure._MethodsData = new LZAri().Decode(this.DataStructure._MethodsData);
				if ((long)this.DataStructure._MethodsData.Length != (long)((ulong)this.UncompressedMethodsBufferLength))
				{
					throw new Exception("Invalid methods buffer!");
				}
				base.DecryptPrevXor(this.DataStructure._MethodsOffsetTable, this.KeyBuff);
				if (base.IsHVMTechnologyEnabled())
				{
					this.HvmTable = this.ReadHVMTable();
						DecodeLegacyTablePrefix(EarlyTokenLayout ? this.DataStructure._MethodsOffsetTable.Length : this.legacyLayout == LegacyLayoutKind.Header104Permuted ? 10 : 20);
				}
                if (EarlyInlineLayout && this.legacyLayout != LegacyLayoutKind.Header128Inline &&
                    (this.DataStructure.ProtectionFeatures & ProtectSettings.HVMTechnology) != 0)
                    base.XorSelf(this.DataStructure._MethodsOffsetTable, 0, this.DataStructure._MethodsOffsetTable.Length);
				this.InitializeEncryptionKeys();
			}
			else
			{
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = Compressor.Decompress(this.DataStructure.LEH);
					base.DecryptXor(this.DataStructure.LEH, this.KeyBuff);
				}
				base.DecryptXor(this.DataStructure._MethodsData, this.KeyBuff);
				base.DecryptXor(this.DataStructure._MethodsOffsetTable, this.KeyBuff);
			}
			uint[] MethodsOffsets = new uint[this.DataStructure.MethodsCount];
			Buffer.BlockCopy(this.DataStructure._MethodsOffsetTable, 0, MethodsOffsets, 0, this.DataStructure._MethodsOffsetTable.Length);
			using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(this.DataStructure._MethodsData)))
			{
				int i = 0;
				while (i < MethodsOffsets.Length)
				{
					if (MethodsOffsets[i] != 0U)
					{
                        uint descriptorItem = MethodsOffsets[i];
						if (base.IsEnterpriseEdition())
						{
							if (MethodsOffsets[i] >> 28 == 2U)
							{
                                if (EarlyInlineLayout)
                                {
                                    uint target;
                                    uint recordRva = ResolveEarlyInlineProxy((uint)(i + 1), MethodsOffsets, out target);
                                    this.proxyMethods.Add(target, (uint)(i + 1));
                                    this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)recordRva);
                                }
                                else
                                {
								uint rva = ResolveLegacyRecordRva(MethodsOffsets[i], this.DataStructure.ProtectionSettings);
								this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva);
								byte proxyCipher; uint proxyOffset;
                                ReadLegacyDescriptor(MethodsOffsets[i], out proxyCipher, out proxyOffset);
                                var methodInfo = new MethodsDecrypter.DecrypterBase.methodInfo { DecryptorType = proxyCipher, MethodDataOffset = proxyOffset };
                                binaryReader.BaseStream.Position = (long)((ulong)methodInfo.MethodDataOffset);
								methodInfo.Header = binaryReader.ReadBytes(4);
								if (binaryReader.ReadUInt32() != 4294967295U)
								{
									throw new Exception("Invalid proxy method pointer!");
								}
								if (binaryReader.ReadUInt32() > 0U)
								{
									throw new Exception("Invalid proxy method pointer!");
								}
								byte[] data = binaryReader.ReadBytes(BitConverter.ToInt32(methodInfo.Header, 0) >> 8);
                                byte[] originalProxy = (byte[])data.Clone();
                                if (this.legacyLayout == LegacyLayoutKind.Header104Permuted)
                                    data = DecodeValidatedLegacyPermuted(originalProxy, methodInfo.DecryptorType, candidate => {
                                        if (candidate.Length != 8 || (BitConverter.ToUInt32(candidate, 0) != 656676094U && candidate[0] != 255)) return false;
                                        uint target = (BitConverter.ToUInt32(candidate, 4) ^ this.DataStructure.Encryption_Dword ^ this.DataStructure.ProtectionSettings) & 0xFFFFFF;
                                        return target > 0 && target <= MethodsOffsets.Length && MethodsOffsets[target - 1] >> 28 == 4;
                                    });
                                else if (UsesXorPrefixCipher)
                                {
                                    base.DecryptXor(data, this.KeyBuff);
                                    try { this.DecryptData(data, methodInfo.DecryptorType, false); }
                                    catch (NotImplementedException) { data = (byte[])originalProxy.Clone(); }
                                    catch (NotSupportedException) { data = (byte[])originalProxy.Clone(); }
                                }
                                else if (this.legacy112Layout) this.DecodeLegacy112Cipher(data, methodInfo.DecryptorType);
								else
								{
									base.DecryptXor(data, this.KeyBuff);
									base.DecryptPrevXor(data, this.KeyBuff);
									this.DecryptData2(data, (int)methodInfo.DecryptorType, false);
								}
								Array.Resize<byte>(ref data, data.Length);
                                if ((UsesXorPrefixCipher || EarlyTokenLayout) && !IsValidLegacyProxy(data, MethodsOffsets))
                                    data = InferCipher(originalProxy, methodInfo.DecryptorType, candidate => {
                                        return IsValidLegacyProxy(candidate, MethodsOffsets);
                                    });
								if (BitConverter.ToUInt32(data, 0) != 656676094U && (BitConverter.ToUInt32(data, 0) & 255U) != 255U)
								{
									throw new Exception("Invalid dummy value!");
								}
								uint num = BitConverter.ToUInt32(data, 4);
								num = (num ^ ((this.DataStructure.Encryption_Dword ^ this.DataStructure.ProtectionSettings) & 16777215U)) & 16777215U;
								uint value = (uint)(i + 1);
								this.proxyMethods.Add(num, value);
								if (MethodsOffsets[(int)(num - 1U)] >> 28 == 4U || MethodsOffsets[(int)(num - 1U)] >> 28 == 12U)
								{
									rva = (MethodsOffsets[(int)(num - 1U)] ^ this.DataStructure.Encryption_Dword ^ this.value3) & 16777215U;
                                    descriptorItem = MethodsOffsets[(int)(num - 1U)];
									this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva);
								}
                                }
							}
							else if (MethodsOffsets[i] >> 28 == 1U)
							{
								uint rva2 = ResolveLegacyRecordRva(MethodsOffsets[i], this.DataStructure.Encryption_Dword);
								this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva2);
							}
							else
							{
								if (MethodsOffsets[i] >> 28 == 4U || (EarlyInlineLayout && MethodsOffsets[i] >> 28 == 5U))
								{
									goto IL_0F53;
								}
								if (MethodsOffsets[i] >> 28 == 6U)
								{
									this.fakeMethods.Add(i);
									goto IL_0F53;
								}
								if (MethodsOffsets[i] >> 28 == 12U)
								{
									this.secureMethods.Add(i);
									goto IL_0F53;
								}
								if (MethodsOffsets[i] >> 24 == 248U)
								{
									if (MethodsOffsets[i] == 0xF8F00000 && this.module.ResolveMethod((uint)(i + 1)).DeclaringType.FullName.Contains("ZYXDNGuarder")) goto IL_0F53;
									this._anonymous_tokens.Add((uint)(i + 1), (uint)((ulong)(MethodsOffsets[i] & 16777215U) ^ (ulong)((long)(i + 1))));
									goto IL_0F53;
								}
								uint rva3 = ResolveLegacyRecordRva(MethodsOffsets[i], this.DataStructure.Encryption_Dword);
								this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva3);
							}
						}
						else
						{
							if (MethodsOffsets[i] >> 24 == 248U)
							{
								this._anonymous_tokens.Add((uint)(i + 1), (uint)((ulong)(MethodsOffsets[i] & 16777215U) ^ (ulong)((long)(i + 1))));
								goto IL_0F53;
							}
							this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)MethodsOffsets[i]);
						}
						byte methodCipher; uint methodOffset;
                            ReadLegacyDescriptor(descriptorItem, out methodCipher, out methodOffset);
                            var methodInfo2 = new MethodsDecrypter.DecrypterBase.methodInfo { DecryptorType = methodCipher, MDToken = new MDToken(i + 1), MethodDataOffset = methodOffset, Method = this.module.ResolveMethod((uint)(i + 1)) };
                            int MethodBodySize = 0;
						binaryReader.BaseStream.Position = (long)((ulong)methodInfo2.MethodDataOffset);
						methodInfo2.Header = binaryReader.ReadBytes(4);
						int hInt = BitConverter.ToInt32(methodInfo2.Header, 0) >> 8; if (ConsoleLog.Verbose) Console.WriteLine("RECORD RID=" + (i + 1) + " offset=" + methodOffset + " header=" + BitConverter.ToString(methodInfo2.Header));
						methodInfo2.Method_Locals = new List<Local>();
						if (base.IsHVMTechnologyEnabled())
						{
							if ((methodInfo2.Header[0] & 8) == 0)
							{
								using (BinaryReader binaryReader2 = new BinaryReader(new MemoryStream(this.DataStructure.LEH)))
								{
									binaryReader2.BaseStream.Position = (long)hInt;
									short LocalsSize2 = 0;
									short EHSize2 = 0;
									if (EarlyTokenLayout || this.legacyLayout == LegacyLayoutKind.Header160Separated || this.legacyLayout == LegacyLayoutKind.Header160Permuted || this.legacyLayout == LegacyLayoutKind.Header112Standard)
									{
										MethodBodySize = binaryReader2.ReadInt32() >> 8;
										binaryReader2.ReadInt16();
										LocalsSize2 = binaryReader2.ReadInt16();
										EHSize2 = binaryReader2.ReadInt16();
										short finalLocalCount = binaryReader2.ReadInt16();
										if (this.legacy112Layout)
										{
											if (LocalsSize2 != finalLocalCount * 4 || finalLocalCount < 0)
												throw new InvalidDataException("Invalid legacy local descriptor count.");
											LocalsSize2 = finalLocalCount;
										}
									}
									else if (this.legacyLayout == LegacyLayoutKind.Header104Standard || this.legacyLayout == LegacyLayoutKind.Header104Reordered || this.legacyLayout == LegacyLayoutKind.Header104Wide || this.legacyLayout == LegacyLayoutKind.Header104Shifted || this.legacyLayout == LegacyLayoutKind.Header104Permuted)
									{
										LocalsSize2 = binaryReader2.ReadInt16();
										binaryReader2.ReadInt16();
										MethodBodySize = binaryReader2.ReadInt32() >> 8;
										binaryReader2.ReadInt16();
										EHSize2 = binaryReader2.ReadInt16();
									}
									else if (this.legacyLayout != LegacyLayoutKind.Header108)
									{
										if (this.legacyLayout != LegacyLayoutKind.Header124Direct)
										{
											if (this.legacyLayout == LegacyLayoutKind.Header124Alternate || this.legacyLayout == LegacyLayoutKind.Header124Unencrypted)
											{
											}
										}
									}
									if (LocalsSize2 > 0)
									{
										using (BinaryReader localReader = new BinaryReader(new MemoryStream(this.DataStructure.LEH)))
										{
											for (int j = 0; j < (int)LocalsSize2; j++)
											{
												uint offset = binaryReader2.ReadUInt32();
												localReader.BaseStream.Position = (long)((ulong)(this.LEHLocalsOffset + (offset & 16777215U)));
												byte[] local = localReader.ReadBytes((int)((offset >> 24) * 4U));
												methodInfo2.Method_Locals.Add(new Local(SignatureReader.ReadTypeSig(this.module, local)));
											}
										}
									}
									methodInfo2.MethodEH = ((EHSize2 == 0) ? null : binaryReader2.ReadBytes((int)EHSize2));
									methodInfo2.HvmTokenTableOffset = binaryReader.ReadUInt32();
									if (this.legacy112Layout && methodInfo2.HvmTokenTableOffset != uint.MaxValue)
										methodInfo2.MethodHvmTokens = ReadLegacy112Tokens(methodInfo2.HvmTokenTableOffset, out methodInfo2.HvmTokenTableSize);
									else if (!this.legacy112Layout) methodInfo2.HvmTokenTableSize = binaryReader.ReadUInt32();
									methodInfo2.MethodData = binaryReader.ReadBytes(MethodBodySize);
									if (!this.legacy112Layout && base.IsHVMTechnologyEnabled() && methodInfo2.HvmTokenTableOffset != 4294967295U && methodInfo2.HvmTokenTableSize > 0U)
									{
										methodInfo2.MethodHvmTokens = this.ParseHVMTableAtOffset(this.HvmTable, methodInfo2.HvmTokenTableOffset, methodInfo2.HvmTokenTableSize);
									}
								}
							}
							else
							{
								MethodBodySize = hInt;
								methodInfo2.HvmTokenTableOffset = binaryReader.ReadUInt32();
								if (this.legacy112Layout && methodInfo2.HvmTokenTableOffset != uint.MaxValue)
									methodInfo2.MethodHvmTokens = ReadLegacy112Tokens(methodInfo2.HvmTokenTableOffset, out methodInfo2.HvmTokenTableSize);
								else if (!this.legacy112Layout) methodInfo2.HvmTokenTableSize = binaryReader.ReadUInt32();
								methodInfo2.MethodData = binaryReader.ReadBytes(hInt);
								if (!this.legacy112Layout && base.IsHVMTechnologyEnabled() && methodInfo2.HvmTokenTableOffset != 4294967295U && methodInfo2.HvmTokenTableSize > 0U)
								{
									methodInfo2.MethodHvmTokens = this.ParseHVMTableAtOffset(this.HvmTable, methodInfo2.HvmTokenTableOffset, methodInfo2.HvmTokenTableSize);
								}
							}
						}
						else if ((methodInfo2.Header[0] & 8) == 0)
						{
							using (BinaryReader binaryReader3 = new BinaryReader(new MemoryStream(this.DataStructure.LEH)))
							{
								binaryReader3.BaseStream.Position = (long)hInt;
								short LocalsSize2 = 0;
								short EHSize2 = 0;
								if (EarlyInlineLayout) { MethodBodySize = binaryReader3.ReadInt32() >> 8; LocalsSize2 = binaryReader3.ReadInt16(); binaryReader3.ReadInt16(); EHSize2 = binaryReader3.ReadInt16(); binaryReader3.ReadInt16(); } else if (EarlyTokenLayout || this.legacyLayout == LegacyLayoutKind.Header160Separated || this.legacyLayout == LegacyLayoutKind.Header160Permuted || this.legacyLayout == LegacyLayoutKind.Header112Standard)
								{
									MethodBodySize = binaryReader3.ReadInt32() >> 8;
									short usless = binaryReader3.ReadInt16();
									LocalsSize2 = binaryReader3.ReadInt16();
									EHSize2 = binaryReader3.ReadInt16();
									short uselss2 = binaryReader3.ReadInt16();
								}
								else if (this.legacyLayout == LegacyLayoutKind.Header104Standard || this.legacyLayout == LegacyLayoutKind.Header104Reordered || this.legacyLayout == LegacyLayoutKind.Header104Wide || this.legacyLayout == LegacyLayoutKind.Header104Shifted || this.legacyLayout == LegacyLayoutKind.Header104Permuted)
								{
									int crap = binaryReader3.ReadInt32();
									MethodBodySize = binaryReader3.ReadInt32() >> 8;
									LocalsSize2 = binaryReader3.ReadInt16();
									EHSize2 = binaryReader3.ReadInt16();
								}
								else if (this.legacyLayout == LegacyLayoutKind.Header108)
								{
									int crap = binaryReader3.ReadInt32();
									EHSize2 = binaryReader3.ReadInt16();
									LocalsSize2 = binaryReader3.ReadInt16();
									MethodBodySize = binaryReader3.ReadInt32() >> 8;
								}
								else if (this.legacyLayout == LegacyLayoutKind.Header124Direct)
								{
									EHSize2 = binaryReader3.ReadInt16();
									short value2 = binaryReader3.ReadInt16();
									MethodBodySize = binaryReader3.ReadInt32() >> 8;
									LocalsSize2 = binaryReader3.ReadInt16();
									binaryReader3.ReadInt16();
								}
								else if (this.legacyLayout == LegacyLayoutKind.Header124Alternate || this.legacyLayout == LegacyLayoutKind.Header124Unencrypted)
								{
									MethodBodySize = binaryReader3.ReadInt32() >> 8;
									short ehClauseCount = binaryReader3.ReadInt16(); 
									binaryReader3.ReadInt16();                       
									EHSize2 = binaryReader3.ReadInt16();             
									LocalsSize2 = binaryReader3.ReadInt16();         
								}
								methodInfo2.MethodData = binaryReader.ReadBytes(MethodBodySize);
								IList<TypeSig> locals = ((LocalSig)SignatureReader.ReadSig(this.module, binaryReader3.ReadBytes((int)LocalsSize2))).GetLocals();
								for (int k = 0; k < locals.Count; k++)
								{
									methodInfo2.Method_Locals.Add(new Local(locals[k]));
								}
								methodInfo2.MethodEH = ((EHSize2 == 0) ? null : binaryReader3.ReadBytes((int)EHSize2));
							}
						}
						else
						{
							MethodBodySize = hInt;
							methodInfo2.MethodData = binaryReader.ReadBytes(hInt);
						}
						binaryReader.BaseStream.Position = (long)((ulong)(methodInfo2.MethodDataOffset + 4U) + (ulong)(base.IsHVMTechnologyEnabled() ? (this.legacy112Layout ? 4L : 8L) : 0L));
						methodInfo2.MethodData = binaryReader.ReadBytes(Convert.ToInt32((long)(MethodBodySize + 7) & unchecked((long)(ulong)(-8))));
						if (this.legacyPackedRecords) methodInfo2.MethodData = DecodeLegacyPackedMethod(methodInfo2.MethodData, methodInfo2, MethodBodySize);
                                else if (EarlyCipherLayout) methodInfo2.MethodData = DecodeValidatedModernMethod(methodInfo2.MethodData, methodInfo2, MethodBodySize);
                                else if (UsesXorPrefixCipher) methodInfo2.MethodData = DecodeLegacyPackedMethod(methodInfo2.MethodData, methodInfo2, MethodBodySize);
                                else if (this.legacy112Layout) this.DecodeLegacy112Cipher(methodInfo2.MethodData, methodInfo2.DecryptorType);
						else this.DecryptData2(methodInfo2.MethodData, (int)methodInfo2.DecryptorType, true);
						Array.Resize<byte>(ref methodInfo2.MethodData, MethodBodySize);
						this.methodInfos.Add((uint)(i + 1), methodInfo2);
					}
					IL_0F53:
					i++;
					continue;
				}
			}
		}
    }
}
