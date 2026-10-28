#if NET6_0_OR_GREATER
#nullable disable
#endif
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DNGuard_Unpacker
{
    
    internal static class MemberNameNormalizer
    {
        [Flags]
        private enum ReflectionScope { None = 0, PublicFields = 1, NonPublicFields = 2, PublicMethods = 4, NonPublicMethods = 8 }

        internal static int Run(ModuleDefMD module) => RunCore(module, false);
        internal static int RunAll(ModuleDefMD module) => RunCore(module, true);

        private static int RunCore(ModuleDefMD module, bool renameAll)
        {
            var instructions = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
                .SelectMany(m => m.Body.Instructions).ToArray();
            var reflectionNames = new HashSet<string>(StringComparer.Ordinal);
            var reflectionScope = ReflectionScope.None;
            
            
            
            
            foreach (var method in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
                for (int index = 0; index < method.Body.Instructions.Count; index++)
                {
                    var call = method.Body.Instructions[index].Operand as IMethod;
                    if (call == null || !IsNameLookup(call)) continue;
                    string name = ReflectionName(method.Body, index, call);
                    if (!renameAll)
                    {
                        if (name == null) reflectionScope |= UnknownReflectionScope(method.Body, index, call);
                        else reflectionNames.Add(name);
                    }
                }

            var fields = new Dictionary<FieldDef, string>();
            var methods = new Dictionary<MethodDef, string>();
            foreach (var type in module.GetTypes())
            {
                var occupied = new HashSet<string>(type.Fields.Select(f => f.Name.String)
                    .Concat(type.Methods.Select(m => m.Name.String)).Concat(type.Properties.Select(p => p.Name.String))
                    .Concat(type.Events.Select(e => e.Name.String)).Concat(type.NestedTypes.Select(t => t.Name.String))
                    .Concat(new[] { type.Name.String }), StringComparer.Ordinal);
                foreach (var field in type.Fields)
                    if (!type.IsSerializable &&
                        !type.CustomAttributes.IsDefined("System.Runtime.Serialization.DataContractAttribute") &&
                        NeedsName(field.Name.String) && !reflectionNames.Contains(field.Name.String) &&
                        (reflectionScope & (field.IsPublic ? ReflectionScope.PublicFields : ReflectionScope.NonPublicFields)) == 0)
                        fields.Add(field, Allocate("field_", field.Rid, occupied));
                foreach (var method in type.Methods)
                    if (!method.IsConstructor && !method.IsVirtual && !method.HasOverrides &&
                        !method.HasImplMap && !method.IsSpecialName && !method.IsRuntimeSpecialName &&
                        NeedsName(method.Name.String) && !reflectionNames.Contains(method.Name.String) &&
                        (reflectionScope & (method.IsPublic ? ReflectionScope.PublicMethods : ReflectionScope.NonPublicMethods)) == 0)
                        methods.Add(method, Allocate("method_", method.Rid, occupied));
            }

            
            
            var references = module.GetMemberRefs().Concat(instructions.Select(i => i.Operand).OfType<MemberRef>())
                .Concat(instructions.Select(i => i.Operand).OfType<MethodSpec>().Select(m => m.Method).OfType<MemberRef>())
                .Distinct().ToArray();
            var renamedReferences = new Dictionary<MemberRef, string>();
            var changedNames = new HashSet<string>(fields.Keys.Select(f => f.Name.String)
                .Concat(methods.Keys.Select(m => m.Name.String)), StringComparer.Ordinal);
            foreach (var reference in references)
            {
                if (!changedNames.Contains(reference.Name.String)) continue;
                TypeDef owner;
                try
                {
                    var declaringType = reference.DeclaringType;
                    owner = declaringType == null ? null : declaringType.Scope == module
                        ? module.GetTypes().SingleOrDefault(t => t.FullName == declaringType.FullName)
                        : declaringType.ResolveTypeDef();
                    if (owner == null && declaringType is TypeSpec) owner = declaringType.ResolveTypeDef();
                }
                catch (AssemblyResolveException) { continue; }
                if (owner == null || owner.Module != module) continue;
                var comparer = new SigComparer();
                string after;
                if (reference.IsFieldRef)
                {
                    var definition = owner.Fields.FirstOrDefault(f => f.Name == reference.Name && comparer.Equals(f.FieldSig, reference.FieldSig));
                    if (definition != null && fields.TryGetValue(definition, out after)) renamedReferences[reference] = after;
                }
                else if (reference.IsMethodRef)
                {
                    var definition = owner.Methods.FirstOrDefault(m => m.Name == reference.Name && comparer.Equals(m.MethodSig, reference.MethodSig));
                    if (definition != null && methods.TryGetValue(definition, out after)) renamedReferences[reference] = after;
                }
            }
            foreach (var pair in renamedReferences) pair.Key.Name = pair.Value;
            foreach (var pair in fields) pair.Key.Name = pair.Value;
            foreach (var pair in methods) pair.Key.Name = pair.Value;
            return fields.Count + methods.Count;
        }

        private static bool NeedsName(string name)
        {
            
            return !name.StartsWith("<", StringComparison.Ordinal) &&
                !Regex.IsMatch(name, @"^[\p{L}_][\p{L}\p{Nd}\p{Mn}\p{Mc}\p{Pc}\p{Cf}_]*$");
        }

        private static string Allocate(string prefix, uint rid, HashSet<string> occupied)
        {
            uint next = Math.Max(1U, rid);
            while (true)
            {
                string name = prefix + next.ToString(CultureInfo.InvariantCulture);
                if (occupied.Add(name)) return name;
                next = checked(next + 1);
            }
        }

        private static bool IsNameLookup(IMethod method)
        {
            string owner = method.DeclaringType == null ? "" : method.DeclaringType.FullName;
            return (owner == "System.Type" || owner == "System.Reflection.TypeInfo" ||
                owner == "System.Reflection.RuntimeReflectionExtensions") &&
                (method.Name == "GetField" || method.Name == "GetMethod" || method.Name == "GetMember" ||
                 method.Name == "GetProperty" || method.Name == "GetEvent" || method.Name == "InvokeMember" ||
                 method.Name == "GetDeclaredField" || method.Name == "GetDeclaredMethod" ||
                 method.Name == "GetRuntimeField" || method.Name == "GetRuntimeMethod");
        }

        private static string ReflectionName(CilBody body, int callIndex, IMethod call)
        {
            var signature = call.MethodSig;
            if (signature == null) return null;
            int parameter = -1;
            for (int i = 0; i < signature.Params.Count; i++)
                if (signature.Params[i].ElementType == ElementType.String) { parameter = i; break; }
            if (parameter < 0) return null;
            var argument = ReflectionArgument(body, callIndex, signature, parameter);
            return argument != null && argument.OpCode.Code == Code.Ldstr ? argument.Operand as string : null;
        }

        private static ReflectionScope UnknownReflectionScope(CilBody body, int callIndex, IMethod call)
        {
            bool fields = call.Name.String.Contains("Field") || call.Name == "GetMember" || call.Name == "InvokeMember";
            bool methods = call.Name.String.Contains("Method") || call.Name == "GetMember" || call.Name == "InvokeMember";
            bool publicAccess = true, nonPublicAccess = call.DeclaringType.FullName != "System.Type";
            var signature = call.MethodSig;
            if (signature == null) return ReflectionScope.PublicFields | ReflectionScope.NonPublicFields | ReflectionScope.PublicMethods | ReflectionScope.NonPublicMethods;
            for (int parameter = 0; parameter < signature.Params.Count; parameter++)
                if (signature.Params[parameter].FullName == "System.Reflection.BindingFlags")
                {
                    var argument = ReflectionArgument(body, callIndex, signature, parameter);
                    int flags;
                    if (TryConstantInt(body, callIndex, argument, out flags))
                    {
                        publicAccess = (flags & 16) != 0;
                        nonPublicAccess = (flags & 32) != 0;
                        if (call.Name == "InvokeMember")
                        {
                            fields = (flags & (1024 | 2048)) != 0;
                            methods = (flags & 256) != 0;
                        }
                    }
                    else { publicAccess = true; nonPublicAccess = true; }
                    break;
                }
            var result = ReflectionScope.None;
            if (fields && publicAccess) result |= ReflectionScope.PublicFields;
            if (fields && nonPublicAccess) result |= ReflectionScope.NonPublicFields;
            if (methods && publicAccess) result |= ReflectionScope.PublicMethods;
            if (methods && nonPublicAccess) result |= ReflectionScope.NonPublicMethods;
            return result;
        }

        private static bool TryConstantInt(CilBody body, int callIndex, Instruction argument, out int value)
        {
            value = 0;
            if (argument == null) return false;
            if (argument.IsLdcI4()) { value = argument.GetLdcI4Value(); return true; }
            if (!argument.IsLdloc()) return false;
            var local = argument.GetLocal(body.Variables);
            for (int i = body.Instructions.IndexOf(argument) - 1; i >= 0; i--)
            {
                var previous = body.Instructions[i];
                if (previous.OpCode.FlowControl == FlowControl.Branch || previous.OpCode.FlowControl == FlowControl.Cond_Branch ||
                    previous.OpCode.FlowControl == FlowControl.Return || previous.OpCode.FlowControl == FlowControl.Throw) return false;
                if (previous.IsStloc() && previous.GetLocal(body.Variables) == local)
                {
                    if (i == 0 || !body.Instructions[i - 1].IsLdcI4()) return false;
                    value = body.Instructions[i - 1].GetLdcI4Value(); return true;
                }
            }
            return false;
        }

        private static Instruction ReflectionArgument(CilBody body, int callIndex, MethodSig signature, int parameter)
        {
            int depth = signature.Params.Count - 1 - parameter;
            for (int i = callIndex - 1; i >= 0; i--)
            {
                var instruction = body.Instructions[i];
                if (instruction.OpCode.FlowControl == FlowControl.Branch || instruction.OpCode.FlowControl == FlowControl.Cond_Branch ||
                    instruction.OpCode.FlowControl == FlowControl.Return || instruction.OpCode.FlowControl == FlowControl.Throw) return null;
                int pushes, pops;
                instruction.CalculateStackUsage(out pushes, out pops);
                if (pops < 0) return null;
                if (depth < pushes) return instruction;
                depth = depth - pushes + pops;
            }
            return null;
        }
    }
}
