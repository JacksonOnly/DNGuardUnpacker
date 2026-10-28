using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DNGuard_Unpacker
{
    
    
    
    
    internal static class ProvenFakeTypeCleanup
    {
        internal static int Run(ModuleDefMD module, byte[] table, uint encryption, MethodDef initialize)
        {
            if (table == null || table.Length % 4 != 0) return 0;
            var candidates = module.GetTypes().Where(t => !t.IsGlobalModuleType && !t.IsPublic && !t.IsNestedPublic &&
                t.Methods.Count != 0 &&
                t.Methods.All(m => ProvenMethod(module, m, table, encryption, initialize))).ToArray();
            int removed = 0;
            foreach (var type in candidates)
            {
                if (type.NestedTypes.Count != 0 || ReferencedOutside(module, type))
                {
                    
                    
                    
                    if (type.BaseType?.FullName != "System.Object" || type.Interfaces.Count != 0 || MethodsReferenced(module, type)) continue;
                    int methods = type.Methods.Count;
                    type.Methods.Clear(); type.Properties.Clear(); type.Events.Clear();
                    Console.WriteLine("CLEANUP proven fake methods=" + methods + " retained field-holder=" + type.FullName + " fields=" + type.Fields.Count);
                    removed++;
                    continue;
                }
                if (type.DeclaringType == null) module.Types.Remove(type);
                else type.DeclaringType.NestedTypes.Remove(type);
                removed++;
            }
            return removed;
        }

        private static bool MethodsReferenced(ModuleDefMD module, TypeDef type)
        {
            var methods = new HashSet<MethodDef>(type.Methods);
            Func<IMethod, bool> refers = m => m != null && methods.Contains(m.ResolveMethodDef());
            Func<IEnumerable<CustomAttribute>, bool> attributes = list => list.Any(a => refers(a.Constructor));
            if (methods.Contains(module.EntryPoint) || attributes(module.CustomAttributes) ||
                (module.Assembly != null && attributes(module.Assembly.CustomAttributes))) return true;
            foreach (var member in module.GetMemberRefs())
                if (member.IsMethodRef && refers(member)) return true;
            foreach (var owner in module.GetTypes())
            {
                if (attributes(owner.CustomAttributes) || owner.GenericParameters.Any(g => attributes(g.CustomAttributes) ||
                    g.GenericParamConstraints.Any(c => attributes(c.CustomAttributes)))) return true;
                if (owner.Fields.Any(f => attributes(f.CustomAttributes)) || owner.Properties.Any(p => attributes(p.CustomAttributes)) ||
                    owner.Events.Any(e => attributes(e.CustomAttributes))) return true;
                if (owner != type && (owner.Properties.Any(p => p.GetMethods.Concat(p.SetMethods).Concat(p.OtherMethods).Any(m => methods.Contains(m))) ||
                    owner.Events.Any(e => new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod }.Concat(e.OtherMethods).Any(m => m != null && methods.Contains(m))))) return true;
                foreach (var method in owner.Methods)
                {
                    if (attributes(method.CustomAttributes) || method.ParamDefs.Any(p => attributes(p.CustomAttributes)) ||
                        method.GenericParameters.Any(g => attributes(g.CustomAttributes) || g.GenericParamConstraints.Any(c => attributes(c.CustomAttributes))) ||
                        method.Overrides.Any(o => refers(o.MethodBody) || refers(o.MethodDeclaration))) return true;
                    if (methods.Contains(method) || !method.HasBody) continue;
                    foreach (var instruction in method.Body.Instructions)
                    {
                        var call = instruction.Operand as IMethod;
                        if (refers(call)) return true;
                        if (call?.DeclaringType.FullName == "System.Activator" && call.Name == "CreateInstance") return true;
                        if (instruction.Operand is string name && (name == type.FullName || name.StartsWith(type.FullName + ",", StringComparison.Ordinal))) return true;
                    }
                }
            }
            return false;
        }

        private static bool ProvenMethod(ModuleDefMD module, MethodDef method, byte[] table, uint encryption, MethodDef initialize)
        {
            if (method.Rid == 0 || method.Rid > table.Length / 4 || !method.HasBody ||
                method.IsVirtual || method.HasOverrides || method.HasImplMap || method.HasDeclSecurities) return false;
            uint entry = BitConverter.ToUInt32(table, checked((int)(method.Rid - 1) * 4));
            var body = method.Body;
            if (entry == 0 && method.IsStaticConstructor && initialize != null && initialize.IsStatic &&
                initialize.MethodSig.Params.Count == 0 && initialize.ReturnType.ElementType == ElementType.Void &&
                body.Instructions.Count == 2 && body.Instructions[0].OpCode == OpCodes.Call &&
                (body.Instructions[0].Operand as IMethod)?.ResolveMethodDef() == initialize &&
                body.Instructions[1].OpCode == OpCodes.Ret && body.ExceptionHandlers.Count == 0 && body.Variables.Count == 0) return true;
            var visited = new HashSet<uint>();
            var current = method;
            while (true)
            {
                if (current == null || current.DeclaringType != method.DeclaringType || current.Rid == 0 ||
                    current.Rid > table.Length / 4 || !visited.Add(current.Rid)) return false;
                entry = BitConverter.ToUInt32(table, checked((int)(current.Rid - 1) * 4));
                if (entry >> 28 != 6) return false;
                uint target = (entry ^ encryption ^ current.Rid) & 0x0FFFFFFF;
                if (target == 0) break;
                if (target > table.Length / 4) return false;
                current = module.ResolveMethod(target);
                
                
                
                if (current == null) return false;
            }
            return body.ExceptionHandlers.Count == 0 && body.Variables.Count == 0 && body.Instructions.Count == 3 &&
                body.Instructions[0].OpCode == OpCodes.Ldstr &&
                body.Instructions[0].Operand as string == "Error, DNGuard Runtime library not loaded!" &&
                body.Instructions[1].OpCode == OpCodes.Newobj &&
                (body.Instructions[1].Operand as IMethod)?.FullName == "System.Void System.Exception::.ctor(System.String)" &&
                body.Instructions[2].OpCode == OpCodes.Throw;
        }

        private static bool ReferencedOutside(ModuleDefMD module, TypeDef target)
        {
            if (module.EntryPoint?.DeclaringType == target || module.ExportedTypes.Any(t => t.FullName == target.FullName)) return true;
            if (AttributesRefer(module.CustomAttributes, target) ||
                (module.Assembly != null && AttributesRefer(module.Assembly.CustomAttributes, target))) return true;
            
            
            foreach (var reference in module.GetMemberRefs())
                if (Refers(reference.DeclaringType, target) || Refers(reference.Signature, target)) return true;
            foreach (var reference in module.GetTypeRefs()) if (Refers(reference, target)) return true;
            foreach (var type in module.GetTypes())
            {
                if (type == target) continue;
                if (type.DeclaringType == target || Refers(type.BaseType, target) ||
                    type.Interfaces.Any(i => Refers(i.Interface, target) || AttributesRefer(i.CustomAttributes, target)) ||
                    AttributesRefer(type.CustomAttributes, target) || GenericParametersRefer(type.GenericParameters, target)) return true;
                foreach (var field in type.Fields)
                    if (Refers(field.FieldSig, target) || AttributesRefer(field.CustomAttributes, target)) return true;
                foreach (var property in type.Properties)
                    if (Refers(property.PropertySig, target) || AttributesRefer(property.CustomAttributes, target) ||
                        property.GetMethods.Concat(property.SetMethods).Concat(property.OtherMethods).Any(m => m.DeclaringType == target)) return true;
                foreach (var ev in type.Events)
                    if (Refers(ev.EventType, target) || AttributesRefer(ev.CustomAttributes, target) ||
                        new[] { ev.AddMethod, ev.RemoveMethod, ev.InvokeMethod }.Concat(ev.OtherMethods).Any(m => m?.DeclaringType == target)) return true;
                foreach (var method in type.Methods)
                {
                    if (Refers(method.MethodSig, target) || AttributesRefer(method.CustomAttributes, target) ||
                        GenericParametersRefer(method.GenericParameters, target) || method.ParamDefs.Any(p => AttributesRefer(p.CustomAttributes, target)) ||
                        method.Overrides.Any(o => Refers(o.MethodBody, target) || Refers(o.MethodDeclaration, target))) return true;
                    if (!method.HasBody) continue;
                    if (method.Body.Variables.Any(v => Refers(v.Type, target)) ||
                        method.Body.ExceptionHandlers.Any(h => Refers(h.CatchType, target))) return true;
                    foreach (var instruction in method.Body.Instructions)
                        if (Refers(instruction.Operand, target) ||
                            (instruction.Operand is string name && (name == target.FullName || name.StartsWith(target.FullName + ",", StringComparison.Ordinal)))) return true;
                }
            }
            return false;
        }

        private static bool GenericParametersRefer(IEnumerable<GenericParam> parameters, TypeDef type)
        {
            return parameters.Any(p => AttributesRefer(p.CustomAttributes, type) ||
                p.GenericParamConstraints.Any(c => Refers(c.Constraint, type) || AttributesRefer(c.CustomAttributes, type)));
        }

        private static bool AttributesRefer(IEnumerable<CustomAttribute> attributes, TypeDef type)
        {
            return attributes.Any(a => Refers(a.Constructor, type) || a.ConstructorArguments.Any(v => ArgumentRefers(v, type)) ||
                a.NamedArguments.Any(v => Refers(v.Type, type) || ArgumentRefers(v.Argument, type)));
        }

        private static bool ArgumentRefers(CAArgument argument, TypeDef type)
        {
            if (Refers(argument.Type, type) || Refers(argument.Value, type)) return true;
            var array = argument.Value as IList<CAArgument>;
            return array != null && array.Any(v => ArgumentRefers(v, type));
        }

        private static bool Refers(object value, TypeDef type, int depth = 0)
        {
            if (value == null) return false;
            if (depth > 64) return true;
            var signature = value as TypeSig;
            if (signature != null)
            {
                var generic = signature as GenericInstSig;
                var modifier = signature as ModifierSig;
                var function = signature as FnPtrSig;
                return Refers(signature.Next, type, depth + 1) ||
                    (signature is TypeDefOrRefSig token && Refers(token.TypeDefOrRef, type, depth + 1)) ||
                    (generic != null && (Refers(generic.GenericType, type, depth + 1) || generic.GenericArguments.Any(a => Refers(a, type, depth + 1)))) ||
                    (modifier != null && Refers(modifier.Modifier, type, depth + 1)) ||
                    (function != null && Refers(function.Signature, type, depth + 1));
            }
            var specification = value as TypeSpec;
            if (specification != null) return Refers(specification.TypeSig, type, depth + 1);
            var tokenType = value as ITypeDefOrRef;
            if (tokenType != null) return tokenType.ResolveTypeDef() == type;
            var method = value as IMethod;
            if (method != null)
            {
                var instance = method as MethodSpec;
                return Refers(method.DeclaringType, type, depth + 1) || Refers(method.MethodSig, type, depth + 1) ||
                    (instance != null && Refers(instance.GenericInstMethodSig, type, depth + 1));
            }
            var field = value as IField;
            if (field != null) return Refers(field.DeclaringType, type, depth + 1) || Refers(field.FieldSig, type, depth + 1);
            var callable = value as MethodBaseSig;
            if (callable != null) return Refers(callable.RetType, type, depth + 1) || callable.Params.Any(p => Refers(p, type, depth + 1)) ||
                (callable.ParamsAfterSentinel != null && callable.ParamsAfterSentinel.Any(p => Refers(p, type, depth + 1)));
            var fieldSig = value as FieldSig;
            if (fieldSig != null) return Refers(fieldSig.Type, type, depth + 1);
            var arguments = value as GenericInstMethodSig;
            return arguments != null && arguments.GenericArguments.Any(a => Refers(a, type, depth + 1));
        }
    }
}
