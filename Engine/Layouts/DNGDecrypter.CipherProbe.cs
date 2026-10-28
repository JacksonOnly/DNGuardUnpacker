using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using DNGuard_Unpacker.Versions;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        private bool recoveredModernBlock;
        private readonly Dictionary<int, CipherChoice> inferredCiphers = new Dictionary<int, CipherChoice>();
        private readonly Dictionary<int, List<CipherChoice>> equivalentCiphers = new Dictionary<int, List<CipherChoice>>();
        private sealed class CipherChoice
        {
            internal ModernCipherSelection Selection;
            internal bool LengthFirst;
            internal int LegacyId = -1;
            internal bool LegacyUsesPrimary;
            internal int Prefix;
            internal int EarlyNativeId = -1;
        }

        private IEnumerable<CipherChoice> CipherChoices()
        {
            
            
            if (EarlyCipherLayout)
                foreach (int id in new[] { 1, 6, 8 })
                    yield return new CipherChoice { EarlyNativeId = id };
            foreach (var original in ProfileCipherChoices())
                for (int prefix = 0; prefix < (EarlyCipherLayout || UsesXorPrefixCipher ? 4 : 1); prefix++)
                    yield return new CipherChoice { Selection = original.Selection, LengthFirst = original.LengthFirst, Prefix = prefix };
            if (EarlyCipherLayout || UsesXorPrefixCipher || (this.modernLayout && Profile.ProbeLegacyCiphers))
            {
                foreach (int id in new[] { 0, 1, 2, 4, 6, 8, 9, 10, 11, 12, 13, 14 })
                    for (int prefix = 0; prefix < 4; prefix++) yield return new CipherChoice { LegacyId = id, Prefix = prefix };
                foreach (int id in new[] { 0, 1, 2, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15 })
                    for (int prefix = 0; prefix < 4; prefix++) yield return new CipherChoice { LegacyId = id, LegacyUsesPrimary = true, Prefix = prefix };
            }
        }

        private byte[] DecodeChoice(byte[] encoded, CipherChoice choice)
        {
            var bytes = (byte[])encoded.Clone();
            if (choice.EarlyNativeId >= 0)
                return DecodeEarlyNative(bytes, this.KeyBuff, this.DataStructure.Encryption_Dword, choice.EarlyNativeId);
            if (choice.Prefix == 1) DecryptXor(bytes, this.KeyBuff);
            if (choice.Prefix == 2) DecryptPrevXor(bytes, this.KeyBuff);
            if (choice.Prefix == 3) DecryptNextXor(bytes, this.KeyBuff);
            if (choice.LegacyId >= 0)
            {
                if (choice.LegacyUsesPrimary) DecryptData(bytes, choice.LegacyId, false);
                else DecryptData2(bytes, choice.LegacyId, false);
                return bytes;
            }
            return DecodeModernCipherChoice(bytes, choice.Selection, choice.LengthFirst);
        }
        private IEnumerable<CipherChoice> ProfileCipherChoices()
        {
            var seen = new HashSet<string>();
            foreach (var profile in ModernVersionRegistry.Profiles)
                foreach (bool lengthFirst in new[] { false, true })
                    for (int id = 0; id < 16; id++)
                    {
                        ModernCipherSelection s;
                        try { s = profile.SelectCipher(id, lengthFirst); }
                        catch (NotSupportedException) { continue; }
                        string identity = s.Id + ":" + s.BlowfishMode + ":" + s.LegacyBlowfish + ":" + s.LegacyCipherId + ":" + s.SpecialRotatingXXTea + ":" + s.ForceRotatingXXTea + ":" + lengthFirst;
                        if (seen.Add(identity)) yield return new CipherChoice { Selection = s, LengthFirst = lengthFirst };
                    }
        }

        private byte[] DecodeModernProxy(byte[] encoded, int id)
        {
            Func<byte[], bool> valid = bytes => bytes.Length == 8 &&
                (BitConverter.ToUInt32(bytes, 0) == 0x272414FE || bytes[0] == 255) &&
                ((BitConverter.ToUInt32(bytes, 4) ^ this.DataStructure.Encryption_Dword ^ this.DataStructure.ProtectionSettings) & 0xFFFFFF) > 0 &&
                ((BitConverter.ToUInt32(bytes, 4) ^ this.DataStructure.Encryption_Dword ^ this.DataStructure.ProtectionSettings) & 0xFFFFFF) <= this.DataStructure.MethodsCount;
            CipherChoice cached;
            if (this.inferredCiphers.TryGetValue(id, out cached))
            {
                if (this.modernLayout && Profile.RefineEquivalentCiphers) return InferCipher(encoded, id, valid);
                byte[] earlier = DecodeChoice(encoded, cached);
                if (valid(earlier)) return earlier;
            }
            try
            {
                byte[] known = DecodeModernCipher(encoded, id);
                if (valid(known)) return known;
                if (!this.recoveredModernBlock) return known;
            }
            catch (NotSupportedException) { }
            return InferCipher(encoded, id, valid);
        }

        private byte[] DecodeValidatedModernMethod(byte[] encoded, methodInfo info, int length)
        {
            CipherChoice inferred;
            byte[] known;
            bool previouslyInferred = this.inferredCiphers.TryGetValue(info.DecryptorType, out inferred);
            if (previouslyInferred && this.modernLayout && Profile.RefineEquivalentCiphers)
                return InferCipher(encoded, info.DecryptorType, bytes => ValidDecodedMethod(bytes, info), length);
            if (previouslyInferred)
                known = DecodeChoice(encoded, inferred);
            else
            {
                try { known = DecodeModernCipher(encoded, info.DecryptorType); }
                catch (NotSupportedException) { known = null; }
            }
            if (known != null)
            {
                Array.Resize(ref known, length);
                if ((!previouslyInferred && !this.recoveredModernBlock && !EarlyCipherLayout && !this.requireValidatedRuntimeMethods) || ValidDecodedMethod(known, info)) return known;
                if (this.modernLayout && Profile.ProbeTableFeedback && !this.modernTokenSaltKnown &&
                    this.methodInfos.Count == 0 && info.Method.IsInstanceConstructor &&
                    info.Method.MethodSig.Params.Count == 0 && info.MethodHvmTokens != null)
                {
                    InferConstructorTokenSalt(encoded, info, length);
                    if (ValidDecodedMethod(known, info)) return known;
                }
                if (this.modernLayout && Profile.ProbeTableFeedback && !this.modernTokenSaltKnown &&
                    this.methodInfos.Count == 0 && !info.Method.IsInstanceConstructor &&
                    TryInferLaterConstructorTokenSalt(known, info)) return known;
            }
            byte[] found = InferCipher(encoded, info.DecryptorType, bytes => {
                Array.Resize(ref bytes, length);
                return ValidDecodedMethod(bytes, info);
            }, length);
            Array.Resize(ref found, length);
            return found;
        }

        private byte[] InferCipher(byte[] encoded, int id, Func<byte[], bool> valid, int length = -1)
        {
            byte[] selected = null;
            CipherChoice choice = null;
            List<CipherChoice> previousChoices;
            bool refine = this.modernLayout && Profile.RefineEquivalentCiphers;
            var matches = new List<CipherChoice>();
            IEnumerable<CipherChoice> candidates = refine && this.equivalentCiphers.TryGetValue(id, out previousChoices) ? previousChoices : CipherChoices();
            foreach (var candidate in candidates)
            {
                byte[] decoded;
                try { decoded = DecodeChoice(encoded, candidate); if (length >= 0) Array.Resize(ref decoded, length); if (!valid(decoded)) continue; }
                catch (ArgumentException) { continue; }
                catch (InvalidDataException) { continue; }
                catch (NotSupportedException) { continue; }
                catch (OverflowException) { continue; }
                catch (IndexOutOfRangeException) { continue; }
                if (selected != null && !selected.SequenceEqual(decoded)) throw new InvalidDataException("算法 " + id + " 有多个有效明文候选，拒绝猜测。");
                selected = decoded; choice = candidate;
                matches.Add(candidate);
            }
            if (selected == null) throw new NotSupportedException("算法 " + id + " 没有通过格式及 IL 校验的已知算法候选。");
            CipherChoice previous;
            if (this.inferredCiphers.TryGetValue(id, out previous))
            {
                if (refine) this.inferredCiphers[id] = choice;
                else
                {
                    byte[] earlier = DecodeChoice(encoded, previous);
                    if (length >= 0) Array.Resize(ref earlier, length);
                    if (!valid(earlier)) throw new InvalidDataException("同一算法编号的多条记录校验不一致：算法=" + id + "，长度=" + length + "。");
                }
            }
            else
            {
                this.inferredCiphers.Add(id, choice);
                Console.WriteLine("PROBE 已通过唯一明文校验识别算法编号 " + id);
            }
            
            
            if (refine) this.equivalentCiphers[id] = matches;
            return selected;
        }

        private bool ValidDecodedMethod(byte[] bytes, methodInfo info)
        {
            try
            {
                var check = info; check.MethodData = bytes;
                var reader = new MethodReader(this.module, check, info.Method.Parameters, this);
                reader.Read(info.Method);
                var temporary = new MethodDefUser(info.Method.Name, info.Method.MethodSig);
                temporary.Body = new CilBody();
                reader.RestoreMethod(temporary);
                var body = temporary.Body;
                if (body == null || body.Instructions.Count == 0) return false;
                var finalFlow = body.Instructions[body.Instructions.Count - 1].OpCode.FlowControl;
                if (finalFlow != FlowControl.Return && finalFlow != FlowControl.Throw && finalFlow != FlowControl.Branch) return false;
                var members = new HashSet<Instruction>(body.Instructions);
                foreach (var instruction in body.Instructions)
                {
                    var code = instruction.OpCode.Code;
                    if (code == Code.UNKNOWN1 || code == Code.UNKNOWN2 ||
                        code == Code.Prefix1 || code == Code.Prefix2 || code == Code.Prefix3 || code == Code.Prefix4 ||
                        code == Code.Prefix5 || code == Code.Prefix6 || code == Code.Prefix7 || code == Code.Prefixref) return false;
                    if ((code >= Code.Ldloc_0 && code <= Code.Ldloc_3) || (code >= Code.Stloc_0 && code <= Code.Stloc_3))
                        if (instruction.GetLocal(body.Variables) == null) return false;
                    if (code >= Code.Ldarg_0 && code <= Code.Ldarg_3)
                        if (instruction.GetParameter(info.Method.Parameters) == null) return false;
                    if (instruction.OpCode.OperandType != OperandType.InlineNone && instruction.Operand == null) return false;
                    if (instruction.Operand is Instruction target && !members.Contains(target)) return false;
                    if (instruction.Operand is IList<Instruction> targets && targets.Any(t => !members.Contains(t))) return false;
                }
                uint maximum;
                return MaxStackCalculator.GetMaxStack(body.Instructions, body.ExceptionHandlers, out maximum);
            }
            catch (Exception) { return false; }
        }
    }
}
