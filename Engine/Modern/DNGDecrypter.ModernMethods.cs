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
		private void ReadModernMethods()
		{
			this.InitializeEncryptionKeys();
			this.ValidateMethodDataBounds();
			DataReader methodReader = this.externalMethods != null ? ByteArrayDataReaderFactory.CreateReader(this.externalMethods) : this.reader;
			methodReader.Position = this.externalMethods != null ? 0 : (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.MethodsDataOffset);
			byte[] table = methodReader.ReadBytes(checked((int)this.DataStructure.MethodsCount * 4));
			byte[] methods = new LZAri().Decode(methodReader.ReadBytes((int)this.DataStructure.MethodsBufferLength));
			if ((uint)methods.Length != this.UncompressedMethodsBufferLength) throw new InvalidDataException("Modern methods decompressed length mismatch.");
			byte[] leh = this.DataStructure.LEHSize == 0 ? new byte[0] : new LZAri().Decode(methodReader.ReadBytes((int)this.DataStructure.LEHSize));
            if (Profile.HasTerminalTokenTable && (this.LEHLocalsOffset > this.HvmTokenTableOffset ||
                (ulong)this.HvmTokenTableOffset + this.HvmTokenTableSize != (ulong)leh.Length))
                throw new InvalidDataException("局部签名及 token 表边界与解压后的 LEH 不一致。");
            if (Profile is DirectHeader124FeedbackProfile)
            {
                modernTableProbeMethods = methods;
                modernTableProbeLeh = (byte[])leh.Clone();
                DecryptPrevXor(modernTableProbeLeh, this.KeyBuff);
            }
            try { DecodeModernMethodTable(table); }
            finally { modernTableProbeMethods = null; modernTableProbeLeh = null; }

			base.XorSelf(table, 0, 9);
			base.DecryptPrevXor(leh, this.KeyBuff);
			this.DataStructure.LEH = leh;
            this.DataStructure._MethodsOffsetTable = table;
            this.DataStructure._MethodsData = methods;
            SelectModernTokenOffsetShift(table, methods, leh);
			for (uint rid = 1; rid <= this.DataStructure.MethodsCount; rid++)
			{
				uint item = BitConverter.ToUInt32(table, (int)(rid - 1) * 4);
				if (item == 0) continue;
				MethodDef method = this.module.ResolveMethod(rid);
				if (method == null) throw new InvalidDataException("Unknown modern method RID " + rid);
				if ((item >> 24) == 0xF8)
				{
					if (!method.DeclaringType.FullName.Contains("ZYXDNGuarder"))
						this._anonymous_tokens.Add(rid, (item & 0xFFFFFF) ^ rid);
					else if (item != 0xF8F00000) this._anonymous_tokens.Add(rid, (item & 0xFFFFFF) ^ rid);
					continue;
				}
				uint kind = (item >> 28) & Profile.KindMask;
				if (kind == 6) { this.modernFakeMethods.Add(rid); continue; }
				if (kind != 0 && kind != 1 && kind != 2 && kind != 4 && kind != 5)
					throw new NotSupportedException("Unsupported modern method table kind " + kind + " at RID " + rid);
				byte decryptor;
				int offset = this.ReadModernRecordOffset(methods, item, rid, out decryptor);
				RequireModernRange(methods, offset, 8, rid, "method record");
				uint header = BitConverter.ToUInt32(methods, offset);
				if (kind == 2)
				{
					int proxyLength = checked((int)(header >> 8));
					if ((header & 8) == 0 || proxyLength != 8 || BitConverter.ToUInt32(methods, offset + 4) != uint.MaxValue)
						throw new InvalidDataException("Invalid modern proxy record at RID " + rid);
					var encodedProxy = new byte[8];
					RequireModernRange(methods, offset + 8L, 8, rid, "proxy payload");
					Buffer.BlockCopy(methods, offset + 8, encodedProxy, 0, 8);
					byte[] proxy = this.DecodeModernProxy(encodedProxy, decryptor);

					if (BitConverter.ToUInt32(proxy, 0) != 0x272414FE && proxy[0] != 0xFF)
						throw new InvalidDataException("Invalid modern proxy marker at RID " + rid);
					uint target = (BitConverter.ToUInt32(proxy, 4) ^ this.DataStructure.Encryption_Dword ^ this.DataStructure.ProtectionSettings) & 0xFFFFFF;
					if (target == 0 || target > this.DataStructure.MethodsCount) throw new InvalidDataException("Invalid modern proxy target at RID " + rid);
					uint targetItem = BitConverter.ToUInt32(table, (int)(target - 1) * 4);
					uint targetKind = (targetItem >> 28) & Profile.KindMask;
					if (targetKind != 4 && targetKind != 5) throw new NotSupportedException("Unsupported modern proxy target kind at RID " + rid);
					this.proxyMethods.Add(target, rid);
					offset = this.ReadModernRecordOffset(methods, targetItem, rid, out decryptor);
					RequireModernRange(methods, offset, 8, rid, "proxy target record");
					header = BitConverter.ToUInt32(methods, offset);
				}
				if ((header & 15) == 0 && method.DeclaringType.FullName.Contains("ZYXDNGuarder")) continue;
				var mi = new MethodsDecrypter.DecrypterBase.methodInfo();
				mi.Method = method;
				mi.MDToken = method.MDToken;
				mi.Method_Locals = new List<Local>();
				mi.DecryptorType = decryptor;
				int length;
				if ((header & 8) != 0) length = checked((int)(header >> 8));
				else
				{
					int lehOffset = checked((int)(header >> 8));
					RequireModernRange(leh, lehOffset, 12, rid, "LEH header");
					int ehSizeOffset = Profile.EhSizeOffset(this.modernLehLengthFirst);
					int localCountOffset = Profile.LocalCountOffset;
					int ehSize = BitConverter.ToUInt16(leh, lehOffset + ehSizeOffset);
					int localCount = BitConverter.ToUInt16(leh, lehOffset + localCountOffset);
					length = checked((int)(BitConverter.ToUInt32(leh, lehOffset + Profile.MethodLengthOffset(this.modernLehLengthFirst)) >> 8));
					int cursor = lehOffset + 12;
					if (Profile.DescriptorSizeOffset >= 0)
					{
						int descriptorSizeOffset = Profile.DescriptorSizeOffset;
						if (BitConverter.ToUInt16(leh, lehOffset + descriptorSizeOffset) != localCount * 4)
							throw new InvalidDataException("Invalid modern local descriptor size at RID " + rid);
					}
					RequireModernRange(leh, cursor, (long)localCount * 4 + ehSize, rid, "locals and EH records");
					for (int local = 0; local < localCount; local++, cursor += 4)
					{
						uint spec = BitConverter.ToUInt32(leh, cursor);
						int sigOffset = checked((int)(this.LEHLocalsOffset + (spec & 0xFFFFFF)));
						byte[] sig = new byte[checked((int)(spec >> 24) * 4)];
						RequireModernRange(leh, sigOffset, sig.Length, rid, "local signature");
						Buffer.BlockCopy(leh, sigOffset, sig, 0, sig.Length);
						mi.Method_Locals.Add(new Local(SignatureReader.ReadTypeSig(this.module, sig, GenericParamContext.Create(method))));
					}
					if (ehSize != 0)
					{
						mi.MethodEH = new byte[ehSize];
						Buffer.BlockCopy(leh, cursor, mi.MethodEH, 0, ehSize);
					}
				}
				uint tokenOffset = BitConverter.ToUInt32(methods, offset + 4);
                Console.WriteLine("RECORD rid=" + rid + " offset=0x" + offset.ToString("X") + " header=0x" + header.ToString("X") + " tokens=0x" + tokenOffset.ToString("X"));
				if (tokenOffset != uint.MaxValue)
				{
					int cursor = checked((int)(this.HvmTokenTableOffset + (tokenOffset >> EffectiveTokenOffsetShift)));
					RequireModernRange(leh, cursor, 4, rid, "token count");
					uint count = BitConverter.ToUInt32(leh, cursor) ^ this.value3;
					if (count > (leh.Length - cursor - 4) / 4) throw new InvalidDataException("方法 token 数量无效：RID=" + rid + "，偏移=0x" + cursor.ToString("X") + "，数量=" + count + "。");
					mi.MethodHvmTokens = new uint[count];
					for (int index = 0; index < count; index++) mi.MethodHvmTokens[index] = BitConverter.ToUInt32(leh, cursor + 4 + index * 4);
					mi.HvmTokenTableSize = count;
					mi.HvmTokenTableOffset = tokenOffset;
                    mi.ModernTokenIndices = BuildModernTokenIndices(mi.MethodHvmTokens, (tokenOffset & 1U) != 0);
				}
				byte[] encoded = new byte[checked((length + 7) & ~7)];
				RequireModernRange(methods, offset + 8L, encoded.Length, rid, "method payload");
				Buffer.BlockCopy(methods, offset + 8, encoded, 0, encoded.Length);
                if ((Profile.ProbeTokenSalt || this.recoveredTableFeedbackWidth != 0 || this.recoveredTokenOffsetShift >= 0) && !this.modernTokenSaltKnown) InferModernTokenSalt(encoded, mi, length);
				mi.MethodData = DecodeValidatedModernMethod(encoded, mi, length);
				this.methodInfos.Add(rid, mi);
			}
		}

        private int[] BuildModernTokenIndices(uint[] words, bool pairedMembers)
        {
            var indices = new List<int>();
            for (int physical = 0; physical < words.Length;)
            {
                indices.Add(physical);
                uint kind = (words[physical] >> 28) & Profile.KindMask;
                int width = pairedMembers && kind >= 3 && kind <= 7 ? 2 : 1;
                if (physical + width > words.Length) throw new InvalidDataException("Truncated modern paired token.");
                physical += width;
            }
            return indices.ToArray();
        }

        private void DecodeModernMethodTable(byte[] table)
        {
            byte[] encoded = (byte[])table.Clone();
            TransformModernFeedback(encoded, table, Profile.TableFeedbackWidth, Profile.TableFeedbackInitial);
            if (ValidateDecodedModernProbeTable(table)) return;
            if (!Profile.ProbeTableFeedback) throw new InvalidDataException("方法表未通过描述符及范围校验。");

            
            
            
            byte[] selected = null;
            byte selectedInitial = 0;
            for (int initial = 0; initial <= byte.MaxValue; initial++)
            {
                var candidate = new byte[encoded.Length];
                TransformModernFeedback(encoded, candidate, 2, (byte)initial);
                if (!ValidateDecodedModernProbeTable(candidate)) continue;
                if (selected != null && !selected.SequenceEqual(candidate))
                    throw new InvalidDataException("方法表反馈初始状态存在歧义。");
                selected = candidate;
                selectedInitial = (byte)initial;
            }
            if (selected == null) throw new InvalidDataException("方法表未通过描述符及范围校验。");
            Buffer.BlockCopy(selected, 0, table, 0, table.Length);
            this.recoveredTableFeedbackWidth = 2;
            this.recoveredTableFeedbackInitial = selectedInitial;
            this.recoveredModernBlock = true;
            if (!this.suppressLayoutLog) Console.WriteLine("PROBE 方法表反馈已通过全部描述符校验；width=2 initial=" + selectedInitial);
        }

        private int recoveredTableFeedbackWidth;
        private byte[] modernTableProbeMethods;
        private byte[] modernTableProbeLeh;
        private byte recoveredTableFeedbackInitial;
        private int recoveredTokenOffsetShift = -1;
        private int EffectiveTableFeedbackWidth => recoveredTableFeedbackWidth == 0 ? Profile.TableFeedbackWidth : recoveredTableFeedbackWidth;
        private byte EffectiveTableFeedbackInitial => recoveredTableFeedbackWidth == 0 ? Profile.TableFeedbackInitial : recoveredTableFeedbackInitial;
        private int EffectiveTokenOffsetShift => recoveredTokenOffsetShift >= 0 ? recoveredTokenOffsetShift :
            recoveredTableFeedbackWidth == 0 ? Profile.TokenOffsetShift : Profile.RecoveredTableTokenOffsetShift;

        private void SelectModernTokenOffsetShift(byte[] table, byte[] methods, byte[] leh)
        {
            if (!Profile.ProbeTokenOffsetShift || ValidModernTokenOffsets(table, methods, leh, EffectiveTokenOffsetShift)) return;
            int alternate = EffectiveTokenOffsetShift == 0 ? 1 : 0;
            if (!ValidModernTokenOffsets(table, methods, leh, alternate))
                throw new InvalidDataException("方法 token 偏移没有通过全部记录的范围及数量校验。");
            
            
            this.recoveredTokenOffsetShift = alternate;
            this.recoveredModernBlock = true;
            if (!this.suppressLayoutLog) Console.WriteLine("PROBE token 偏移已通过全部记录校验；shift=" + alternate);
        }

        private bool ValidModernTokenOffsets(byte[] table, byte[] methods, byte[] leh, int shift)
        {
            try
            {
                for (uint rid = 1; rid <= this.DataStructure.MethodsCount; rid++)
                {
                    uint item = BitConverter.ToUInt32(table, checked((int)(rid - 1) * 4));
                    if (item == 0 || (item >> 24) == 0xF8 || ((item >> 28) & Profile.KindMask) == 6) continue;
                    byte decryptor;
                    int record = ReadModernRecordOffset(methods, item, rid, out decryptor);
                    RequireModernRange(methods, record, 8, rid, "token offset record");
                    if ((BitConverter.ToUInt32(methods, record) & 15) == 0 &&
                        this.module.ResolveMethod(rid).DeclaringType.FullName.Contains("ZYXDNGuarder")) continue;
                    uint offset = BitConverter.ToUInt32(methods, record + 4);
                    if (offset == uint.MaxValue) continue;
                    long cursor = (long)this.HvmTokenTableOffset + (offset >> shift);
                    RequireModernRange(leh, cursor, 4, rid, "token count");
                    uint count = BitConverter.ToUInt32(leh, (int)cursor) ^ this.value3;
                    RequireModernRange(leh, cursor + 4, (long)count * 4, rid, "token words");
                }
                return true;
            }
            catch (InvalidDataException) { return false; }
            catch (OverflowException) { return false; }
        }

        private void TransformModernFeedback(byte[] encoded, byte[] decoded, int width, byte initial)
        {
            for (int i = 0; i < decoded.Length; i++)
                decoded[i] = (byte)(encoded[i] ^ this.KeyBuff[i % this.KeyBuff.Length] ^
                    (i < width ? initial : encoded[i - width]));
        }

		private int ReadModernRecordOffset(byte[] methods, uint item, uint rid, out byte decryptor)
		{
			int offset = this.ReadModernDescriptor(item, rid, out decryptor);
			int prefixLength = (decryptor & 0x80) != 0 ? 4 : 0;
			
			if ((item & 0x08000000) != 0) prefixLength += 4;
			RequireModernRange(methods, offset, prefixLength, rid, "record prefixes");
			decryptor &= 0x7F;
			return checked(offset + prefixLength);
		}

		private int ReadModernDescriptor(uint item, uint rid, out byte decryptor)
		{
			uint kind = (item >> 28) & Profile.KindMask;
			uint mask = kind == 2 ? this.DataStructure.ProtectionSettings : this.DataStructure.Encryption_Dword;
			
			if (kind == 4 || kind == 5) mask ^= this.value3;
			uint rva = (item ^ mask) & 0xFFFFFF;
			uint raw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva);
			if (raw == 0 || (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)raw) != rva || (ulong)raw + 6 > this.reader.Length)
				throw new InvalidDataException(string.Format("Invalid modern descriptor RVA 0x{0:X8} at RID {1} (item 0x{2:X8}).", rva, rid, item));
			this.reader.Position = raw;
			uint descriptor = this.reader.ReadUInt32();
			decryptor = (byte)descriptor;
			if (decryptor != 254) return checked((int)(descriptor >> 8) * 8);
			decryptor = (byte)(descriptor >> 8);
			this.reader.Position -= 2;
			uint offset = this.reader.ReadUInt32();
			if (offset > int.MaxValue) throw new InvalidDataException("Invalid modern method offset at RID " + rid);
			return (int)offset;
		}

		private static void RequireModernRange(byte[] data, long offset, long length, uint rid, string field)
		{
			if (offset < 0 || length < 0 || offset > data.LongLength || length > data.LongLength - offset)
				throw new InvalidDataException(string.Format("Modern {0} outside buffer at RID {1}: offset=0x{2:X}, length={3}, buffer={4}.", field, rid, offset, length, data.Length));
		}
    }
}
