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
		private bool TryModernStructure(byte[] bytes)
		{
			uint[] w = new uint[bytes.Length / 4];
			Buffer.BlockCopy(bytes, 0, w, 0, bytes.Length);
			uint marker = w[0];
                  ModernVersionProfile selectedProfile = null;
                  var directProfiles = ModernVersionRegistry.Profiles.Where(profile => !profile.Chained && profile.HeaderSize == bytes.Length && profile.Marker == marker).ToArray();
                  if (directProfiles.Length != 0)
                  {
                          selectedProfile = directProfiles[0];
                  }
                  else
                  {
                          if (bytes.Length != 124) return false;

                          ModernVersionProfile decodedProfile = null;
                          uint[] decoded = null;
                          foreach (var candidateProfile in ModernVersionRegistry.Profiles.Where(profile => profile.Chained))
                          {
                                  uint candidate = candidateProfile.Marker;
                                  uint chainKey = w[0] ^ candidate;
                                  var candidateWords = new uint[w.Length];
                                  for (int i = 0; i < candidateWords.Length; i++)
                                          candidateWords[i] = w[i] ^ (i == 0 ? 0U : w[i - 1]) ^ chainKey;
                                  int candidateKeyIndex = candidateProfile.KeyIndex;
                                  uint candidateKeyRva = candidateWords[candidateKeyIndex] ^ chainKey;
                                  if (candidateWords[2] != chainKey || !VerifyModernKeyAtRva(candidateKeyRva, chainKey)) continue;
                                  if (decodedProfile != null) throw new InvalidDataException("Ambiguous chained modern header.");
                                  decodedProfile = candidateProfile;
                                  decoded = candidateWords;
                          }
                          if (decoded == null && !TryAutoChainedHeader(w, out decodedProfile, out decoded)) return false;
                          w = decoded;
                          selectedProfile = decodedProfile;
                  }
                  if (selectedProfile == null) return false;
                  this.modernFamily = Array.IndexOf(ModernVersionRegistry.Profiles, selectedProfile);
                  if (selectedProfile.TableFeedbackWidth != 1 || selectedProfile.ValidateDecodedMethods) this.recoveredModernBlock = true;
			this.valueN4 = w[0];
			this.value3 = w[1];
			this.value1 = w[3];
			this.value2 = w[1];
			
			this.DataStructure.Encryption_Dword = w[Profile.EncryptionIndex];
			this.DataStructure.ProtectionSettings = Profile.Settings(w);
			this.DataStructure.ProtectionFeatures = (MethodsDecrypter.DecrypterBase.ProtectSettings)(this.DataStructure.ProtectionSettings & 4095U);
			int keyIndexForProfile = Profile.KeyIndex;
			this.DataStructure.KeyBuffOffset = w[keyIndexForProfile] ^ this.DataStructure.Encryption_Dword;
			this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.KeyBuffOffset);
			this.KeyBuff = this.reader.ReadBytes(20);
			if (!base.VerifyKeyBuffer(this.KeyBuff, this.DataStructure.Encryption_Dword)) throw new InvalidDataException("Modern key checksum mismatch.");
			Array.Resize(ref this.KeyBuff, 16);
			this.DataStructure.MethodsCount = w[Profile.MethodsCountIndex];
			this.UncompressedMethodsBufferLength = w[Profile.ExpandedMethodsIndex];
			
			uint firstRva = Profile.FirstMethodsRva(w, this.DataStructure.ProtectionSettings);
			uint secondRva = Profile.SecondMethodsRva(w, this.DataStructure.ProtectionSettings);
			if (this.externalMethods != null && !base.IsApplicationMode())
				throw new InvalidDataException("External methods require Application Mode.");
			if (this.externalMethods == null && base.IsApplicationMode())
                RecoverExternalMethodsOrThrow(w);
			bool first, second;
			if (Profile.Chained)
			{

				first = false;
				second = this.externalMethods != null ? IsExternalBlockLayout(w[Profile.CompressedMethodsIndex], w[Profile.LehSizeIndex]) :
					IsModernBlockLayout(firstRva, w[Profile.CompressedMethodsIndex], w[Profile.LehSizeIndex]);
                if (!second && this.externalMethods == null)
                {
                    firstRva = FindModernMethodBlock(w[Profile.CompressedMethodsIndex], w[Profile.LehSizeIndex]);
                    second = firstRva != 0;
                    this.recoveredModernBlock = second;
                }
                if (!second) throw new InvalidDataException("Invalid modern 4.9 method block layout.");
			}
			else
			{
				first = this.externalMethods != null ? IsExternalBlockLayout(Profile.CompressedMethodsSize(w, false), w[Profile.LehSizeIndex]) : IsModernBlockLayout(firstRva, Profile.CompressedMethodsSize(w, false), w[Profile.LehSizeIndex]);
				second = Profile.HasAlternateBlockLayout && (this.externalMethods != null ? IsExternalBlockLayout(Profile.CompressedMethodsSize(w, true), w[Profile.LehSizeIndex]) : IsModernBlockLayout(secondRva, Profile.CompressedMethodsSize(w, true), w[Profile.LehSizeIndex]));
                if (!first && !second && firstRva == 0 && !Profile.HasAlternateBlockLayout &&
                    this.externalMethods == null && !base.IsApplicationMode())
                {
                    firstRva = FindModernMethodBlock(Profile.CompressedMethodsSize(w, false), w[Profile.LehSizeIndex], true);
                    first = firstRva != 0;
                    this.recoveredModernBlock = first;
                }
				if (first == second) throw new InvalidDataException("No unique validated modern block layout.");
			}
			this.DataStructure.MethodsDataOffset = Profile.Chained ? firstRva : (first ? firstRva : secondRva);

			this.modernLehLengthFirst = Profile.Chained || second;
			this.DataStructure.MethodsBufferLength = Profile.CompressedMethodsSize(w, second);
			this.DataStructure.LEHSize = w[Profile.LehSizeIndex];

			this.HvmTokenTableSize = w[Profile.TokenSizeIndex];
			this.HvmTokenTableOffset = w[Profile.TokenOffsetIndex];
			this.LEHLocalsOffset = Profile.LocalsOffset(w);
			this.modernLayout = true;
			this.DataStructure.ResourceCount = Profile.ResourceCount(w, second);
			this.DataStructure.ResourceStructureOffset = w[Profile.ResourceOffsetIndex];
			if (this.DataStructure.ResourceCount > this.module.Metadata.TablesStream.ManifestResourceTable.Rows)
				throw new InvalidDataException("Invalid modern resource count.");

			this.DataStructure.StringsOffset = w[Profile.StringsOffsetIndex];

			this.DataStructure.EncryptedStringsSize = Profile.EncryptedStringsSize(w, second);
			if (this.DataStructure.EncryptedStringsSize != 0 && this.DataStructure.StringsOffset != 0)
			{
				uint rawStrings = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.StringsOffset);
				if (rawStrings == 0 || (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)rawStrings) != this.DataStructure.StringsOffset ||
					(ulong)rawStrings + this.DataStructure.EncryptedStringsSize > this.reader.Length)
					throw new InvalidDataException("Modern user-string heap outside module.");
			}
			if (!this.suppressLayoutLog) Console.WriteLine("LAYOUT modern" + Profile.HeaderSize + " settings=" + this.DataStructure.ProtectionSettings.ToString("X8") + (this.externalMethods != null ? " externalMethods=" + this.externalMethods.Length : " methodsRva=" + this.DataStructure.MethodsDataOffset.ToString("X8")));
			return true;
		}

		private bool VerifyModernKeyAtRva(uint rva, uint encryptionDword)
		{
			uint raw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva);
			if (raw == 0 || (ulong)raw + 20UL > this.reader.Length || (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)raw) != rva) return false;
			this.reader.Position = raw;
			return base.VerifyKeyBuffer(this.reader.ReadBytes(20), encryptionDword);
		}

		private bool IsExternalBlockLayout(uint compressedMethods, uint compressedLeh)
		{
			ulong tableLength = (ulong)this.DataStructure.MethodsCount * 4;
			if (tableLength < 12 || this.DataStructure.MethodsCount > this.module.Metadata.TablesStream.MethodTable.Rows ||
				compressedMethods < 4 || (compressedLeh != 0 && compressedLeh < 4) ||
				tableLength + compressedMethods + compressedLeh != (ulong)this.externalMethods.Length) return false;
			if (this.UncompressedMethodsBufferLength == 0 || this.UncompressedMethodsBufferLength > 64 * 1024 * 1024 ||
				BitConverter.ToUInt32(this.externalMethods, (int)tableLength) != this.UncompressedMethodsBufferLength) return false;
			return compressedLeh == 0 || BitConverter.ToUInt32(this.externalMethods, checked((int)(tableLength + compressedMethods))) <= 64 * 1024 * 1024;
		}

		private bool IsModernBlockLayout(uint rva, uint compressedMethods, uint compressedLeh)
		{
			ulong count = this.DataStructure.MethodsCount;
			if (count == 0 || count > this.module.Metadata.TablesStream.MethodTable.Rows || compressedMethods < 4) return false;
			uint raw = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva);
			if ((uint)this.module.Metadata.PEImage.ToRVA((FileOffset)raw) != rva) return false;
			ulong end = raw + count * 4 + compressedMethods + compressedLeh;
			if (raw == 0 || end > this.reader.Length) return false;
			this.reader.Position = checked(raw + (uint)count * 4);
			return this.reader.ReadUInt32() == this.UncompressedMethodsBufferLength;
		}
    }
}
