using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        private uint modernTokenSalt;
        private bool modernTokenSaltKnown;

        
        
        private bool TryInferLaterConstructorTokenSalt(byte[] firstBody, methodInfo firstInfo)
        {
            byte[] table = this.DataStructure._MethodsOffsetTable, methods = this.DataStructure._MethodsData;
            if (table == null || methods == null) return false;
            var salts = new HashSet<uint>();
            uint savedSalt = this.modernTokenSalt;
            bool savedKnown = this.modernTokenSaltKnown;
            try
            {
                for (uint rid = 1; rid <= this.DataStructure.MethodsCount; rid++)
                {
                    var method = this.module.ResolveMethod(rid);
                    if (!method.IsInstanceConstructor || method.MethodSig.Params.Count != 0) continue;
                    uint item = BitConverter.ToUInt32(table, checked((int)(rid - 1) * 4));
                    uint kind = (item >> 28) & Profile.KindMask;
                    if (item == 0 || (kind != 0 && kind != 1)) continue;
                    byte cipher;
                    int offset = ReadModernRecordOffset(methods, item, rid, out cipher);
                    RequireModernRange(methods, offset, 8, rid, "salt-constrained constructor");
                    uint header = BitConverter.ToUInt32(methods, offset);
                    int length = checked((int)(header >> 8));
                    
                    if ((header & 8) == 0 || length < 7 || length > 8) continue;
                    uint tokenOffset = BitConverter.ToUInt32(methods, offset + 4);
                    if (tokenOffset == uint.MaxValue) continue;
                    int cursor = checked((int)(this.HvmTokenTableOffset + (tokenOffset >> EffectiveTokenOffsetShift)));
                    RequireModernRange(this.DataStructure.LEH, cursor, 4, rid, "constructor token count");
                    uint count = BitConverter.ToUInt32(this.DataStructure.LEH, cursor) ^ this.value3;
                    if (count != 1 || (tokenOffset & 1) != 0) continue;
                    RequireModernRange(this.DataStructure.LEH, cursor + 4, 4, rid, "constructor token");
                    var info = new methodInfo { Method = method, MDToken = method.MDToken, DecryptorType = cipher,
                        Method_Locals = new List<dnlib.DotNet.Emit.Local>(), HvmTokenTableOffset = tokenOffset,
                        HvmTokenTableSize = count, MethodHvmTokens = new[] { BitConverter.ToUInt32(this.DataStructure.LEH, cursor + 4) },
                        ModernTokenIndices = new[] { 0 } };
                    byte[] encoded = new byte[(length + 7) & ~7];
                    RequireModernRange(methods, offset + 8L, encoded.Length, rid, "constructor cipher payload");
                    Buffer.BlockCopy(methods, offset + 8, encoded, 0, encoded.Length);
                    try
                    {
                        InferConstructorTokenSalt(encoded, info, length);
                        byte[] body = DecodeModernCipher(encoded, cipher);
                        Array.Resize(ref body, length);
                        if (ValidDecodedMethod(body, info) && ValidDecodedMethod(firstBody, firstInfo)) salts.Add(this.modernTokenSalt);
                    }
                    catch (InvalidDataException) { }
                    catch (NotSupportedException) { }
                    finally { this.modernTokenSalt = savedSalt; this.modernTokenSaltKnown = savedKnown; }
                }
                if (salts.Count > 1) throw new InvalidDataException("后续构造函数约束得到多个 token 掩码。");
                if (salts.Count == 0) return false;
                this.modernTokenSalt = salts.Single(); this.modernTokenSaltKnown = true;
                Console.WriteLine("PROBE 已根据后续构造函数唯一约束 token 掩码；首方法及后续记录逐项校验。");
                return true;
            }
            catch { this.modernTokenSalt = savedSalt; this.modernTokenSaltKnown = savedKnown; throw; }
        }

        
        
        private void InferModernTokenSalt(byte[] encoded, methodInfo info, int length)
        {
            if (TryInferInstanceGetterTokenSalt(encoded, info, length)) return;
            if (info.Method.IsInstanceConstructor && info.Method.MethodSig.Params.Count == 0 && info.MethodHvmTokens != null)
            {
                InferConstructorTokenSalt(encoded, info, length);
                return;
            }
            if (length != 6 || info.Method.MethodSig.HasThis || info.Method.MethodSig.Params.Count != 0 ||
                info.MethodHvmTokens == null)
            {
                byte[] body = DecodeModernCipher(encoded, info.DecryptorType);
                Array.Resize(ref body, length);
                if (TryInferLaterConstructorTokenSalt(body, info)) return;
                throw new NotSupportedException("无法从当前方法签名唯一约束 token 掩码。");
            }
            var comparer = new SigComparer();
            var fields = this.module.GetTypes().SelectMany(t => t.Fields).Where(f => f.IsStatic &&
                comparer.Equals(f.FieldSig.Type, info.Method.MethodSig.RetType)).ToArray();
            var salts = new HashSet<uint>();
            foreach (var choice in CipherChoices())
            {
                byte[] body;
                try { body = DecodeChoice(encoded, choice); }
                catch (ArgumentException) { continue; }
                catch (NotSupportedException) { continue; }
                catch (InvalidDataException) { continue; }
                if (body.Length < length || body[0] != 0x7E || body[5] != 0x2A) continue;
                uint token = BitConverter.ToUInt32(body, 1);
                if ((token >> 24) != 4) continue;
                int logical = (int)(token & 0xFFFFF) - 4;
                if (logical < 0 || logical >= info.ModernTokenIndices.Length) continue;
                uint bits = DecodeModernTokenBits(token, info, info.ModernTokenIndices[logical]);
                foreach (var field in fields)
                    salts.Add((bits ^ (0x40000000U | (field.Rid << 6))) & 0xFFFFFFC0U);
            }
            if (salts.Count != 1) throw new InvalidDataException("token 掩码存在歧义或没有符合静态字段签名的候选。");
            this.modernTokenSalt = salts.Single();
            this.modernTokenSaltKnown = true;
            Console.WriteLine("PROBE 已根据唯一静态字段签名约束 token 掩码；后续逐方法校验。");
        }

        private bool TryInferInstanceGetterTokenSalt(byte[] encoded, methodInfo info, int length)
        {
            if (length != 7 || !info.Method.MethodSig.HasThis || info.Method.MethodSig.Params.Count != 0 || info.MethodHvmTokens == null) return false;
            var comparer = new SigComparer();
            var targets = new List<uint>();
            foreach (var field in info.Method.DeclaringType.Fields.Where(f => !f.IsStatic && comparer.Equals(f.FieldType, info.Method.ReturnType)))
                targets.Add(field.MDToken.Raw);
            foreach (var field in this.module.GetMemberRefs().Where(f => f.IsFieldRef &&
                f.DeclaringType.ResolveTypeDef() == info.Method.DeclaringType && comparer.Equals(f.FieldSig.Type, info.Method.ReturnType)))
                targets.Add(field.MDToken.Raw);
            var salts = new HashSet<uint>();
            uint saved = modernTokenSalt; bool known = modernTokenSaltKnown;
            try
            {
                foreach (var choice in CipherChoices())
                {
                    byte[] body;
                    try { body = DecodeChoice(encoded, choice); }
                    catch (ArgumentException) { continue; }
                    catch (NotSupportedException) { continue; }
                    catch (InvalidDataException) { continue; }
                    if (body.Length < length || body[0] != 0x02 || body[1] != 0x7B || body[6] != 0x2A) continue;
                    uint token = BitConverter.ToUInt32(body, 2);
                    int logical = (int)(token & 0xFFFFF) - 4;
                    if (logical < 0 || logical >= info.ModernTokenIndices.Length) continue;
                    uint bits = DecodeModernTokenBits(token, info, info.ModernTokenIndices[logical]);
                    int kind = (int)(bits >> 28);
                    if (kind >= tokenBases.Length) continue;
                    foreach (uint target in targets.Where(t => (t & 0xFF000000) == tokenBases[kind]))
                    {
                        modernTokenSalt = (bits ^ ((uint)kind << 28) ^ ((target & 0xFFFFFF) << 6)) & 0xFFFFFFC0;
                        modernTokenSaltKnown = true;
                        Array.Resize(ref body, length);
                        if (ValidDecodedMethod(body, info)) salts.Add(modernTokenSalt);
                    }
                }
            }
            finally { modernTokenSalt = saved; modernTokenSaltKnown = known; }
            if (salts.Count == 0) return false;
            if (salts.Count != 1) throw new InvalidDataException("实例字段 getter 约束得到多个 token 掩码。");
            modernTokenSalt = salts.Single(); modernTokenSaltKnown = true;
            Console.WriteLine("PROBE 已根据唯一实例字段 getter 签名约束 token 掩码；后续逐方法校验。");
            return true;
        }

        private void InferConstructorTokenSalt(byte[] encoded, methodInfo info, int length)
        {
            var comparer = new SigComparer();
            var targets = this.module.GetMemberRefs().Where(m => m.IsMethodRef && m.Name == ".ctor" &&
                comparer.Equals(m.DeclaringType, info.Method.DeclaringType.BaseType) &&
                m.MethodSig.HasThis && m.MethodSig.Params.Count == 0).ToArray();
            var salts = new HashSet<uint>();
            foreach (var choice in CipherChoices())
            {
                byte[] body;
                try { body = DecodeChoice(encoded, choice); }
                catch (ArgumentException) { continue; }
                catch (NotSupportedException) { continue; }
                catch (InvalidDataException) { continue; }
                if (length < 7 || body.Length < length || body[0] != 0x02 || body[1] != 0x28 || body[length - 1] != 0x2A) continue;
                uint token = BitConverter.ToUInt32(body, 2);
                if ((token >> 24) != 0x0A) continue;
                int logical = (int)(token & 0xFFFFF) - 4;
                if (logical < 0 || logical >= info.ModernTokenIndices.Length) continue;
                uint bits = DecodeModernTokenBits(token, info, info.ModernTokenIndices[logical]);
                int kind = (int)(bits >> 28);
                if (kind >= tokenBases.Length || tokenBases[kind] != 0x0A000000) continue;
                foreach (var target in targets)
                    salts.Add((bits ^ ((uint)kind << 28) ^ (target.Rid << 6)) & 0xFFFFFFC0U);
            }
            if (salts.Count != 1) throw new InvalidDataException("基类构造函数无法唯一约束 token 掩码。");
            this.modernTokenSalt = salts.Single();
            this.modernTokenSaltKnown = true;
            Console.WriteLine("PROBE 已根据唯一基类构造函数约束 token 掩码；后续逐方法校验。");
        }
    }
}
