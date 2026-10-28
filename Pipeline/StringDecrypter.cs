using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DNGuard_Unpacker
{
    internal static class StringDecrypter
    {
        public static void Decrypt(ModuleDefMD module, IDecrypter decrypter)
        {
            var tokens = decrypter.GetAnonymousTokens();
            int replaced = 0;
            foreach (var type in module.GetTypes())
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    foreach (var instruction in method.Body.Instructions)
                    {
                        var target = instruction.Operand as MethodDef;
                        uint offset;
                        if (instruction.OpCode != OpCodes.Call || target == null || !tokens.TryGetValue(target.MDToken.Rid, out offset)) continue;
                        if (target.MethodSig.Params.Count != 0 || (target.MethodSig.RetType.ElementType != ElementType.String && target.MethodSig.RetType.ElementType != ElementType.Object))
                            throw new NotSupportedException("Unknown anonymous-token call signature: " + target.FullName + " (RID " + target.Rid + ", offset 0x" + offset.ToString("X") + ") in " + method.FullName + ".");
                        string value = decrypter.ReadUserStringFromOffset(offset);
                        if (value == null) throw new System.IO.InvalidDataException("Invalid anonymous string at offset 0x" + offset.ToString("X") + " in " + method.FullName + " (target RID " + target.Rid + ").");
                        instruction.OpCode = OpCodes.Ldstr;
                        instruction.Operand = value;
                        replaced++;
                    }
                }
            Console.WriteLine("STRINGS replaced=" + replaced);
        }
    }
}
