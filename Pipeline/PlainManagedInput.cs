using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace DNGuard_Unpacker
{
    
    public static class PlainManagedInput
    {
        public static bool IsReadable(ModuleDefMD module)
        {
            if (!module.IsILOnly) return false;
            var image = module.Metadata.PEImage;
            var metadata = image.CreateReader(module.Metadata.ImageCor20Header.Metadata.VirtualAddress, 4);
            if (metadata.ReadUInt32() != 0x424A5342) return false;
            uint raw = (uint)image.ToFileOffset(module.Metadata.ImageCor20Header.Metadata.VirtualAddress);
            if (raw >= 16 && image.CreateReader((dnlib.IO.FileOffset)(raw - 16), 4).ReadUInt32() == 0x424A5342) return false;
            if (image.ImageSectionHeaders.Any(s => s.DisplayName.StartsWith(".hvm", StringComparison.OrdinalIgnoreCase) ||
                s.DisplayName.IndexOf("dng", StringComparison.OrdinalIgnoreCase) >= 0)) return false;
            var methods = module.GetTypes().SelectMany(t => t.Methods).ToArray();
            if (module.GetTypes().Any(t => Suspicious(t.FullName)) ||
                module.GetModuleRefs().Any(r => Suspicious(r.Name)) ||
                methods.Any(m => m.HasImplMap && (Suspicious(m.ImplMap.Name) || Suspicious(m.ImplMap.Module.Name)))) return false;
            
            foreach (var method in methods)
            {
                if (!method.HasBody)
                {
                    if (!method.IsAbstract && !method.IsPinvokeImpl && !method.IsRuntime) return false;
                    continue;
                }
                var body = method.Body;
                if (body.Instructions.Count == 0) return false;
                var last = body.Instructions[body.Instructions.Count - 1];
                if (last.OpCode.FlowControl != FlowControl.Return && last.OpCode.FlowControl != FlowControl.Throw &&
                    last.OpCode.FlowControl != FlowControl.Branch && last.OpCode.Code != Code.Jmp) return false;
                var members = new HashSet<Instruction>(body.Instructions);
                foreach (var ins in body.Instructions)
                {
                    if (ins.OpCode.Code == Code.UNKNOWN1 || ins.OpCode.Code == Code.UNKNOWN2 ||
                        ins.OpCode.Name.StartsWith("prefix", StringComparison.OrdinalIgnoreCase)) return false;
                    if (ins.OpCode.OperandType != OperandType.InlineNone && ins.Operand == null) return false;
                    if (ins.Operand is string text && Suspicious(text)) return false;
                    if (ins.Operand is Instruction target && !members.Contains(target)) return false;
                    if (ins.Operand is IList<Instruction> targets && targets.Any(t => !members.Contains(t))) return false;
                    if (ins.IsLdarg() || ins.IsStarg())
                        if (ins.GetParameter(method.Parameters) == null) return false;
                    if (ins.IsLdloc() || ins.IsStloc())
                        if (ins.GetLocal(body.Variables) == null) return false;
                }
                uint stack;
                if (!MaxStackCalculator.GetMaxStack(body.Instructions, body.ExceptionHandlers, out stack)) return false;
                foreach (var handler in body.ExceptionHandlers)
                {
                    if (handler.TryStart == null || handler.HandlerStart == null ||
                        !members.Contains(handler.TryStart) || !members.Contains(handler.HandlerStart) ||
                        (handler.TryEnd != null && !members.Contains(handler.TryEnd)) ||
                        (handler.HandlerEnd != null && !members.Contains(handler.HandlerEnd)) ||
                        (handler.HandlerType == ExceptionHandlerType.Filter && (handler.FilterStart == null || !members.Contains(handler.FilterStart))) ||
                        (handler.HandlerType == ExceptionHandlerType.Catch && handler.CatchType == null)) return false;
                }
            }
            
            foreach (var resource in module.Resources.OfType<EmbeddedResource>()) resource.CreateReader().ToArray();
            if (methods.Length != 0) return true;
            
            
            
            if (module.Assembly == null || module.ExportedTypes.Count == 0) return false;
            foreach (var exported in module.ExportedTypes)
            {
                var seen = new HashSet<ExportedType>();
                var root = exported;
                while (root.Implementation is ExportedType enclosing)
                {
                    if (!seen.Add(root)) return false;
                    root = enclosing;
                }
                if (!root.IsForwarder || !(root.Implementation is AssemblyRef assembly) ||
                    string.IsNullOrEmpty(assembly.Name) || Suspicious(exported.FullName)) return false;
            }
            return true;
        }

        private static bool Suspicious(string value)
        {
            return value != null && new[] { "DNGuard", "ZYXDN", "NETShieldRT", "HVMRuntime", "HVMRuntm", "HVMRun64", "DNG_Runtime", "CheckRuntime", "RunHVM" }
                .Any(s => value.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0);
        }
    }
}
