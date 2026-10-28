using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.PE;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        
        public static LayoutProbeReport ProbeLayoutDeep(byte[] input, byte[] externalMethods = null)
        {
            byte[] bytes = (byte[])input.Clone();
            LayoutProbeReport report;
            using (var module = ModuleDefMD.Load(bytes)) report = ProbeLayout(module, externalMethods);
            report.DeepValidation = new LayoutDeepEvidence();
            if (!report.Recognized)
            {
                report.DeepValidation.Diagnostic = report.Diagnostic ?? "未识别数据头，无法校验方法和字符串。";
                return report;
            }
            try
            {
                using (var module = ModuleDefMD.Load(bytes))
                {
                    var probe = new DNGDecrypter(module, externalMethods);
                    probe.ParseStructure();
                    probe.DecryptInternal(ref bytes);
                }
                using (var module = ModuleDefMD.Load(bytes))
                {
                    var probe = new DNGDecrypter(module, externalMethods);
                    probe.ParseStructure();
                    
                    
                    
                    probe.RequireValidatedRuntimeMethods();
                    var evidence = report.DeepValidation;
                    evidence.StringsRva = probe.DataStructure.StringsOffset;
                    evidence.StringsSize = probe.DataStructure.EncryptedStringsSize;
                    evidence.CompressedMethodsSize = probe.DataStructure.MethodsBufferLength;
                    evidence.CompressedLehSize = probe.DataStructure.LEHSize;
                    evidence.LocalsOffset = probe.LEHLocalsOffset;
                    evidence.TokenTableOffset = probe.HvmTokenTableOffset;
                    evidence.TokenTableSize = probe.HvmTokenTableSize;
                    if (probe.legacyLayout == LegacyLayoutKind.Header104Permuted)
                    {
                        evidence.TableFeedbackWidth = 1;
                        evidence.TokenOffsetShift = 1;
                        evidence.MethodLengthOffset = 4;
                        evidence.ExceptionSizeOffset = 10;
                        evidence.LocalCountOffset = 0;
                        string[] names = { "key", "encryption", "methods-count", "expanded-methods-size", "methods-table", "compressed-methods-size", "compressed-leh-size", "tokens-offset", "tokens-size", "locals-offset", "strings-rva", "strings-size", "resources-rva", "resources-count" };
                        int[] indices = { 18, 3, 12, 19, 9, 14, 8, 11, 16, 22, 5, 13, 4, 6 };
                        for (int i = 0; i < names.Length; i++) evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = names[i], WordIndex = indices[i] });
                    }
                    if (probe.IsModernLayout)
                    {
                        var profile = probe.Profile;
                        evidence.TableFeedbackWidth = profile.TableFeedbackWidth;
                        evidence.TableFeedbackInitial = profile.TableFeedbackInitial;
                        evidence.TokenOffsetShift = profile.TokenOffsetShift;
                        evidence.MethodLengthOffset = profile.MethodLengthOffset(probe.modernLehLengthFirst);
                        evidence.ExceptionSizeOffset = profile.EhSizeOffset(probe.modernLehLengthFirst);
                        evidence.LocalCountOffset = profile.LocalCountOffset;
                        evidence.LocalDescriptorSizeOffset = profile.DescriptorSizeOffset;
                        evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = "key", WordIndex = profile.KeyIndex });
                        evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = "encryption", WordIndex = profile.EncryptionIndex });
                        evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = "methods-count", WordIndex = profile.MethodsCountIndex });
                        evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = "expanded-methods-size", WordIndex = profile.ExpandedMethodsIndex });
                        evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = "methods-table", WordIndex = profile.TableIndex });
                        evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = "compressed-methods-size", WordIndex = profile.CompressedMethodsIndex });
                        evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = "compressed-leh-size", WordIndex = profile.LehSizeIndex });
                        evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = "tokens-offset", WordIndex = profile.TokenOffsetIndex });
                        evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = "tokens-size", WordIndex = profile.TokenSizeIndex });
                        evidence.HeaderFields.Add(new LayoutFieldEvidence { Name = "strings-rva", WordIndex = profile.StringsOffsetIndex });
                    }
                    try { probe.ReadMethods(); }
                    finally
                    {
                        if (!probe.IsModernLayout)
                        {
                            evidence.TableXorLength = probe.legacyTableXorLength;
                            evidence.PackedLegacyRecords = probe.legacyPackedRecords;
                        }
                    }
                    if (probe.IsModernLayout)
                    {
                        evidence.TableFeedbackWidth = probe.EffectiveTableFeedbackWidth;
                        evidence.TableFeedbackInitial = probe.EffectiveTableFeedbackInitial;
                        evidence.TokenOffsetShift = probe.EffectiveTokenOffsetShift;
                    }
                    foreach (var pair in probe.methodInfos)
                    {
                        if (!probe.ValidDecodedMethod(pair.Value.MethodData, pair.Value))
                            throw new InvalidDataException("恢复的方法未通过 IL、操作数和栈校验：RID=" + pair.Key + "。");
                        evidence.MethodsValidated++;
                    }
                    evidence.TokenSalt = probe.modernTokenSalt;
                    if (probe.IsModernLayout || probe.legacyLayout == LegacyLayoutKind.Header104Permuted)
                        foreach (int id in (probe.IsModernLayout ? probe.methodInfos.Values.Select(m => (int)m.DecryptorType).Concat(probe.inferredCiphers.Keys) : probe.inferredCiphers.Keys).Distinct().OrderBy(i => i))
                        {
                            CipherChoice choice;
                            bool inferred = probe.inferredCiphers.TryGetValue(id, out choice);
                            if (!inferred) choice = new CipherChoice { Selection = probe.Profile.SelectCipher(id, probe.modernLehLengthFirst), LengthFirst = probe.modernLehLengthFirst };
                            var selection = choice.Selection;
                            evidence.Ciphers.Add(new LayoutCipherEvidence {
                                AlgorithmId = id, Inferred = inferred, CipherId = selection == null ? -1 : selection.Id,
                                LegacyCipherId = choice.LegacyId >= 0 ? choice.LegacyId : selection == null ? -1 : selection.LegacyCipherId,
                                LegacyUsesPrimary = choice.LegacyUsesPrimary || (choice.LegacyId < 0 && selection != null && selection.LegacyCipherId >= 0),
                                BlowfishMode = selection == null ? -1 : selection.BlowfishMode,
                                LegacyBlowfish = selection != null && selection.LegacyBlowfish,
                                SpecialRotatingXXTea = selection != null && selection.SpecialRotatingXXTea,
                                ForceRotatingXXTea = selection != null && selection.ForceRotatingXXTea,
                                LengthFirst = choice.LengthFirst, PrefixTransform = choice.Prefix
                            });
                        }
                    foreach (var token in probe.GetAnonymousTokens())
                    {
                        uint size = evidence.StringsRva == 0 ? module.USStream.StreamLength : evidence.StringsSize;
                        uint offset = token.Value;
                        if (offset == 0 || offset > size)
                            throw new InvalidDataException("匿名字符串引用超出声明的数据区：RID=" + token.Key + "，偏移=0x" + offset.ToString("X") + "，数据区长度=" + size + "。");
                        uint raw = evidence.StringsRva == 0 ? (uint)module.USStream.StartOffset : (uint)module.Metadata.PEImage.ToFileOffset((RVA)evidence.StringsRva);
                        var reader = module.Metadata.PEImage.CreateReader();
                        reader.Position = checked(raw + offset - 1);
                        uint length = reader.ReadCompressedUInt32();
                        if (length == 0 || (length & 1) == 0 || (ulong)reader.Position + length > (ulong)raw + size || probe.ReadUserStringFromOffset(offset) == null)
                            throw new InvalidDataException("匿名字符串长度或 UTF-16 格式校验失败：RID=" + token.Key + "。");
                        new System.Text.UnicodeEncoding(false, false, true).GetString(reader.ReadBytes(checked((int)length - 1)));
                        if (reader.ReadByte() > 1) throw new InvalidDataException("匿名字符串终止标志无效：RID=" + token.Key + "。");
                        evidence.AnonymousStringsValidated++;
                    }
                    probe.RestoreMethods();
                    if (probe.methodInfos.Count != 0) throw new InvalidDataException("仍有方法记录未恢复。");
                    StringDecrypter.Decrypt(module, probe);
                    evidence.Succeeded = true;
                }
            }
            catch (Exception error)
            {
                report.DeepValidation.Diagnostic = error.GetType().Name + ": " + error.Message;
            }
            return report;
        }
    }
}
