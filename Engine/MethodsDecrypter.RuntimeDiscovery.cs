using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DNGuard_Unpacker
{
    public partial class MethodsDecrypter
    {
        
        
        private void FindRenamedRuntime()
        {
            var globalConstructor = this.module.GlobalType.FindStaticConstructor();
            if (globalConstructor == null || !globalConstructor.HasBody) return;
            var candidates = globalConstructor.Body.Instructions
                .Where(i => i.OpCode == OpCodes.Call)
                .Select(i => (i.Operand as IMethod)?.ResolveMethodDef())
                .Where(m => m != null && m.IsStatic && !m.IsConstructor && m.HasBody &&
                    m.MethodSig != null && m.MethodSig.Params.Count == 0 && m.MethodSig.RetType.ElementType == ElementType.Void)
                .Distinct().Where(IsRenamedRuntimeInitializer).ToArray();
            if (candidates.Length == 0) return;
            if (candidates.Length != 1) throw new InvalidDataException("多个重命名运行时初始化候选，拒绝选择。");
            this.initializeMethod = candidates[0];
            this.DNGRtType = this.initializeMethod.DeclaringType;
            this.foundRtType = true;
            ((DNGDecrypter)this.decrypter).RequireValidatedRuntimeMethods();
            var native = this.DNGRtType.Methods.Single(m => IsRuntimeImport(m, "CheckRuntime"));
            string location = string.IsNullOrEmpty(this.module.Location) ? Program.path : this.module.Location;
            string directory = string.IsNullOrEmpty(location) ? null : Path.GetDirectoryName(location);
            NativeModulePath32 = string.IsNullOrEmpty(directory) ? native.ImplMap.Module.Name.String :
                Path.Combine(directory, native.ImplMap.Module.Name.String);
            Console.WriteLine("RUNTIME 已通过模块初始化调用及成对原生 API 识别重命名运行时：" + this.DNGRtType.FullName);
        }

        private static bool IsRenamedRuntimeInitializer(MethodDef initializer)
        {
            var type = initializer.DeclaringType;
            if (!type.IsSealed || type.BaseType?.FullName != "System.Object") return false;
            var x86 = type.Methods.Where(m => IsRuntimeImport(m, "CheckRuntime")).ToArray();
            var x64 = type.Methods.Where(m => IsRuntimeImport(m, "CheckRuntime64")).ToArray();
            if (x86.Length != 1 || x64.Length != 1) return false;
            bool sharedEntry = x86[0].ImplMap.Name == "VMRuntime" || x64[0].ImplMap.Name == "VMRuntime";
            if (sharedEntry && (x86[0].ImplMap.Name != "VMRuntime" || x64[0].ImplMap.Name != "VMRuntime" ||
                x86[0].ImplMap.Module.Name != x64[0].ImplMap.Module.Name)) return false;
            var calls = initializer.Body.Instructions.Where(i => i.OpCode == OpCodes.Call)
                .Select(i => (i.Operand as IMethod)?.ResolveMethodDef()).ToArray();
            if (!calls.Contains(x86[0]) || !calls.Contains(x64[0])) return false;
            
            return type.Methods.Any(m => m.IsStatic && m.Name == "CheckString" && m.MethodSig != null &&
                m.MethodSig.Params.Count == 2 && m.MethodSig.Params.All(p => p.ElementType == ElementType.I4) &&
                (m.MethodSig.RetType.ElementType == ElementType.String || m.MethodSig.RetType.ElementType == ElementType.I)) &&
                type.Methods.Any(m => m.IsStatic && m.Name == "RunHVM" && m.MethodSig != null &&
                    m.MethodSig.Params.Count == 0 && m.MethodSig.RetType.ElementType == ElementType.Boolean);
        }

        private static bool IsRuntimeImport(MethodDef method, string entry)
        {
            return method.IsStatic && method.HasImplMap &&
                (method.ImplMap.Name == entry || (method.Name == entry && method.ImplMap.Name == "VMRuntime")) &&
                method.ImplMap.Module != null && !UTF8String.IsNullOrEmpty(method.ImplMap.Module.Name) &&
                method.MethodSig != null && !method.MethodSig.HasThis && method.MethodSig.Params.Count == 1 &&
                method.MethodSig.Params[0].ElementType == ElementType.I4 && method.MethodSig.RetType.ElementType == ElementType.Boolean;
        }
    }
}
