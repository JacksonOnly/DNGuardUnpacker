using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace DNGuard_Unpacker
{
    internal static partial class Program
    {
        private static int NormalizeAsyncReturnTypes(ModuleDef mod)
        {
            int changed = 0;
            foreach (var method in mod.GetTypes().SelectMany(t => t.Methods))
            {
                if (!method.IsPrivate || !method.HasBody || method.ReturnType.ElementType != ElementType.Object ||
                    !method.CustomAttributes.Any(a => a.TypeFullName == "System.Runtime.CompilerServices.AsyncStateMachineAttribute")) continue;
                var instructions = method.Body.Instructions;
                if (instructions.Count < 2 || instructions[instructions.Count - 1].OpCode != OpCodes.Ret ||
                    instructions[instructions.Count - 2].OpCode != OpCodes.Call) continue;
                var task = instructions[instructions.Count - 2].Operand as IMethod;
                if (task == null || task.Name != "get_Task" || task.MethodSig == null || task.MethodSig.Params.Count != 0 ||
                    !task.DeclaringType.FullName.StartsWith("System.Runtime.CompilerServices.AsyncTaskMethodBuilder", StringComparison.Ordinal) ||
                    !task.MethodSig.RetType.FullName.StartsWith("System.Threading.Tasks.Task", StringComparison.Ordinal)) continue;

                TypeSig returnType = task.MethodSig.RetType;
                var resultTask = returnType as GenericInstSig;
                if (resultTask != null)
                {
                    var builderSpec = task.DeclaringType as TypeSpec;
                    var builder = builderSpec == null ? null : builderSpec.TypeSig as GenericInstSig;
                    if (builder == null || builder.GenericType.FullName != "System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1" ||
                        builder.GenericArguments.Count != 1 || resultTask.GenericType.FullName != "System.Threading.Tasks.Task`1" ||
                        resultTask.GenericArguments.Count != 1 || !(resultTask.GenericArguments[0] is GenericVar) ||
                        ((GenericVar)resultTask.GenericArguments[0]).Number != 0) continue;
                    returnType = new GenericInstSig(resultTask.GenericType, builder.GenericArguments[0]);
                }
                else if (returnType.FullName != "System.Threading.Tasks.Task") continue;
                method.ReturnType = returnType;
                changed++;
            }
            return changed;
        }

        private static int NormalizeGeneratedReturnTypes(ModuleDef mod)
        {
            int changed = 0;
            foreach (var method in mod.GetTypes().SelectMany(t => t.Methods))
            {
                if (!method.IsPrivate || !method.HasBody || method.ReturnType.ElementType != ElementType.Object ||
                    !method.CustomAttributes.IsDefined("System.Runtime.CompilerServices.CompilerGeneratedAttribute") ||
                    method.Body.ExceptionHandlers.Count != 0) continue;
                var instructions = method.Body.Instructions;
                if (instructions.Count < 2 || instructions.Last().OpCode != OpCodes.Ret ||
                    instructions.Count(i => i.OpCode.FlowControl == FlowControl.Return) != 1 ||
                    instructions.Any(i => i.OpCode.FlowControl == FlowControl.Cond_Branch) ||
                    instructions.Where(i => i.OpCode.FlowControl == FlowControl.Branch)
                        .Any(i => instructions.IndexOf(i) + 1 >= instructions.Count || i.Operand != instructions[instructions.IndexOf(i) + 1])) continue;
                var producer = instructions[instructions.Count - 2];
                Local returnedLocal = null;
                if (producer.IsLdloc())
                {
                    returnedLocal = producer.GetLocal(method.Body.Variables);
                    var stores = instructions.Where(i => i.IsStloc() && i.GetLocal(method.Body.Variables) == returnedLocal).ToArray();
                    if (returnedLocal == null || stores.Length != 1 || instructions.IndexOf(stores[0]) == 0) continue;
                    producer = instructions[instructions.IndexOf(stores[0]) - 1];
                }
                TypeSig value = null;
                var call = producer.Operand as IMethod;
                var field = producer.Operand as IField;
                if ((producer.OpCode == OpCodes.Call || producer.OpCode == OpCodes.Callvirt) && call != null && call.MethodSig != null)
                    value = call.MethodSig.RetType;
                else if ((producer.OpCode == OpCodes.Ldfld || producer.OpCode == OpCodes.Ldsfld) && field != null && field.FieldSig != null)
                    value = field.FieldSig.Type;
                if (value == null || (value.ElementType != ElementType.Class && value.ElementType != ElementType.String &&
                    value.ElementType != ElementType.SZArray && value.ElementType != ElementType.Array)) continue;
                method.ReturnType = value;
                if (returnedLocal != null) returnedLocal.Type = value;
                changed++;
            }
            return changed;
        }

        private static int NormalizeOptionalConstants(ModuleDef mod)
        {
            int changed = 0;
            foreach (var method in mod.GetTypes().SelectMany(t => t.Methods))
                foreach (var parameter in method.Parameters)
                {
                    var definition = parameter.ParamDef;
                    if (definition == null || !definition.IsOptional || definition.Constant == null ||
                        parameter.Type.RemovePinnedAndModifiers().ElementType != ElementType.U4) continue;

                    object value = definition.Constant.Value;
                    if (value is bool)
                        definition.Constant = new ConstantUser((bool)value ? 1U : 0U);
                    else if (value is int)
                        definition.Constant = new ConstantUser(unchecked((uint)(int)value));
                    else continue;
                    changed++;
                }
            return changed;
        }

        private static void RemoveStartup(ModuleDefMD mod, MethodDef initialize)
        {
            foreach (var m in mod.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
                foreach (var ins in m.Body.Instructions)
                    if (ins.OpCode == OpCodes.Call && ins.Operand == initialize && initialize.MethodSig.Params.Count == 0 && initialize.MethodSig.RetType.ElementType == ElementType.Void)
                    { ins.OpCode = OpCodes.Nop; ins.Operand = null; }
        }

        private static void RemoveUnusedRuntime(ModuleDefMD mod, TypeDef runtime)
        {
            if (runtime == null) return;
            while (runtime.DeclaringType != null && !runtime.DeclaringType.IsGlobalModuleType) runtime = runtime.DeclaringType;
            var runtimeTypes = runtime.GetTypes().ToArray();
            foreach (var method in mod.GetTypes().Where(t => !runtimeTypes.Contains(t)).SelectMany(t => t.Methods).Where(m => m.HasBody))
                foreach (var instruction in method.Body.Instructions)
                {
                    var target = instruction.Operand as IMethod;
                    var field = instruction.Operand as IField;
                    ITypeDefOrRef dependency = target != null ? target.DeclaringType : field != null ? field.DeclaringType : instruction.Operand as ITypeDefOrRef;
                    if (dependency != null && runtimeTypes.Contains(dependency.ResolveTypeDef()))
                        throw new NotSupportedException("Unrestored runtime dependency: " + method.FullName + " -> " + instruction.Operand);
                }
            if (runtime.DeclaringType == null) mod.Types.Remove(runtime);
            else runtime.DeclaringType.NestedTypes.Remove(runtime);
            Console.WriteLine("REMOVED runtime=" + runtime.FullName);
        }

        private static void NormalizeEntryPointName(ModuleDef mod)
        {
            var entry = mod.EntryPoint;
            if (entry == null || entry.Name == "Main") return;
            var signature = entry.MethodSig;
            bool validParameters = signature != null && (signature.Params.Count == 0 ||
                (signature.Params.Count == 1 && signature.Params[0] is SZArraySig &&
                 signature.Params[0].Next.ElementType == ElementType.String));
            if (!entry.IsStatic || entry.IsConstructor || signature == null || signature.GenParamCount != 0 ||
                entry.DeclaringType.HasGenericParameters || !validParameters ||
                (signature.RetType.ElementType != ElementType.Void && signature.RetType.ElementType != ElementType.I4))
                throw new NotSupportedException("Cannot normalize a non-C# entry point: " + entry.FullName);
            var comparer = new SigComparer();
            if (entry.DeclaringType.Methods.Any(m => m != entry && m.Name == "Main" && comparer.Equals(m.MethodSig, signature)))
                throw new NotSupportedException("Entry-point normalization would collide with an existing Main method.");
            Console.WriteLine("NORMALIZE entry point " + entry.FullName + " -> Main");
            entry.Name = "Main";
        }

        private static void ValidateMethodBodies(ModuleDefMD mod, DNGDecrypter decrypter = null)
        {
            int count = 0;
            foreach (var method in mod.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
            {
                var body = method.Body.Instructions;
                if (body.Count == 3 && body[0].OpCode == OpCodes.Ldstr &&
                    body[0].Operand as string == "Error, DNGuard Runtime library not loaded!" &&
                    body[1].OpCode == OpCodes.Newobj && body[2].OpCode == OpCodes.Throw &&
                    (body[1].Operand as IMethod)?.FullName == "System.Void System.Exception::.ctor(System.String)")
                    throw new InvalidDataException("Unrestored DNGuard placeholder in " + method.FullName);
                foreach (var instruction in method.Body.Instructions)
                    if (instruction.OpCode.OperandType != OperandType.InlineNone && instruction.Operand == null)
                        throw new InvalidDataException("Unresolved IL operand in " + method.FullName + " at IL_" + instruction.Offset.ToString("X4"));
                uint maxStack;
                if (!MaxStackCalculator.GetMaxStack(method.Body.Instructions, method.Body.ExceptionHandlers, out maxStack) &&
                    (decrypter == null || !decrypter.TryCalculateLegacy112MaxStack(method, out maxStack)))
                    throw new InvalidDataException("Invalid restored IL stack in " + method.FullName);
                method.Body.MaxStack = checked((ushort)maxStack);
                count++;
            }
            Console.WriteLine("VALIDATED IL methods=" + count);
        }
    }
}
