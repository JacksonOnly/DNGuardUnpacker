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
		public void RemoveModernHelpers()
		{

                        RemoveResourceDecoys();
                        if (!this.modernLayout) return;
			var replacements = new Dictionary<MethodDef, MethodDef>();
			var candidates = new HashSet<MethodDef>();
			var comparer = new SigComparer();
			foreach (var pair in this.proxyMethods)
			{
				MethodDef helper = this.module.ResolveMethod(pair.Key), original = this.module.ResolveMethod(pair.Value);
                if (helper == null || original == null || helper == original || helper.DeclaringType != original.DeclaringType || helper.IsVirtual)
                    throw new InvalidDataException("Invalid modern proxy mapping at RID " + pair.Key);

				replacements.Add(helper, original);
				candidates.Add(helper);
			}
			foreach (uint rid in this.modernFakeMethods.Concat(this._anonymous_tokens.Keys))
			{
				MethodDef helper = this.module.ResolveMethod(rid);
				if (helper != null && helper.Module == this.module && !helper.IsVirtual && !helper.IsConstructor) candidates.Add(helper);
			}
			
			foreach (MethodDef method in this.module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
				foreach (Instruction instruction in method.Body.Instructions.ToArray())
				{
					var target = instruction.Operand as IMethod;
					MethodDef original;
					MethodDef definition = target == null ? null : target.ResolveMethodDef();
                    if (definition == null || !replacements.TryGetValue(definition, out original)) continue;
                    if (!CanReplaceModernProxy(definition, original, comparer))
                        throw new NotSupportedException("Cannot replace referenced modern proxy RID " + definition.Rid + ": " + definition + " -> " + original);
                    var spec = target as MethodSpec;
					if (!comparer.Equals(definition.MethodSig, original.MethodSig))
						RestoreProxyArguments(method, instruction, definition, original, comparer);
					instruction.Operand = spec == null ? (IMethod)original : new MethodSpecUser(original, spec.GenericInstMethodSig);
				}
			var referenced = new HashSet<MethodDef>();
			Action<IMethod> keep = m => { if (m != null) { var definition = m.ResolveMethodDef(); if (definition != null) referenced.Add(definition); } };
			keep(this.module.EntryPoint);
			foreach (TypeDef type in this.module.GetTypes())
			{
				foreach (var property in type.Properties)
				{
					foreach (MethodDef m in property.GetMethods.Concat(property.SetMethods).Concat(property.OtherMethods)) keep(m);
				}
				foreach (var ev in type.Events)
				{
					keep(ev.AddMethod); keep(ev.RemoveMethod); keep(ev.InvokeMethod);
					foreach (MethodDef m in ev.OtherMethods) keep(m);
				}
				foreach (MethodDef method in type.Methods)
				{
					foreach (var ov in method.Overrides) { keep(ov.MethodBody); keep(ov.MethodDeclaration); }
					if (method.HasBody)
						foreach (Instruction instruction in method.Body.Instructions) keep(instruction.Operand as IMethod);
				}
			}
			
			foreach (var attribute in this.module.CustomAttributes) keep(attribute.Constructor);
			foreach (TypeDef type in this.module.GetTypes())
			{
				foreach (var attribute in type.CustomAttributes) keep(attribute.Constructor);
				foreach (MethodDef method in type.Methods)
					foreach (var attribute in method.CustomAttributes) keep(attribute.Constructor);
			}
			int removed = 0;
			foreach (MethodDef helper in candidates)
			{
				if (referenced.Contains(helper)) continue;
				helper.DeclaringType.Methods.Remove(helper);
				removed++;
			}
			Console.WriteLine("CLEANUP helpers=" + removed + " retainedReferenced=" + (candidates.Count - removed));
		}

		private void RemoveResourceDecoys()
		{
			uint count = this.DataStructure.ResourceCount;
			var tables = this.module.Metadata.TablesStream;
			if (tables.ManifestResourceTable.Rows != count + 2 || this.module.Resources.Count != count + 2) return;
			RawManifestResourceRow first, second;
			if (!tables.TryReadManifestResourceRow(count + 1, out first) || !tables.TryReadManifestResourceRow(count + 2, out second) ||
				first.Offset != 0 || first.Implementation != 0 || first.Flags != 1 ||
				second.Offset != 0xFFFFFF || second.Implementation != 4 || second.Flags != 1) return;
			var decoys = this.module.Resources.Skip((int)count).ToArray();
			if (decoys.Any(r => string.IsNullOrEmpty(r.Name.String) || !r.Name.String.All(char.IsControl))) return;
			foreach (var resource in decoys) this.module.Resources.Remove(resource);
			Console.WriteLine("CLEANUP resource decoys=" + decoys.Length);
		}

		private static bool CanReplaceModernProxy(MethodDef helper, MethodDef original, SigComparer comparer)
		{
			if (comparer.Equals(helper.MethodSig, original.MethodSig)) return true;
			var source = helper.MethodSig;
			var target = original.MethodSig;
			if (source == null || target == null || source.CallingConvention != target.CallingConvention ||
				source.GenParamCount != target.GenParamCount || source.Params.Count != target.Params.Count ||
				source.ParamsAfterSentinel != null || target.ParamsAfterSentinel != null ||
				!MatchesErasedReference(source.RetType, target.RetType, comparer)) return false;
			for (int i = 0; i < source.Params.Count; i++)
				if (!MatchesErasedReference(source.Params[i], target.Params[i], comparer)) return false;
			return true;
		}

		private static bool MatchesErasedReference(TypeSig erased, TypeSig original, SigComparer comparer)
		{
			if (comparer.Equals(erased, original)) return true;

			if (erased.ElementType == ElementType.U4 && original.ElementType == ElementType.I4) return true;
			if (erased.ElementType == ElementType.U4 && original.ElementType == ElementType.Boolean) return true;
			if (erased.ElementType != ElementType.Object) return false;
			return original.ElementType == ElementType.String || original.ElementType == ElementType.Class ||
				original.ElementType == ElementType.Array || original.ElementType == ElementType.SZArray;
		}

		private static void RestoreProxyArguments(MethodDef caller, Instruction call, MethodDef helper, MethodDef original, SigComparer comparer)
		{
			if (!helper.MethodSig.Params.Where((p, i) => NeedsProxyArgumentAdaptation(p, original.MethodSig.Params[i], comparer)).Any()) return;
			if (call.OpCode != OpCodes.Call && call.OpCode != OpCodes.Callvirt)
				throw new NotSupportedException("Cannot narrow an erased proxy signature for " + call.OpCode + " in " + caller.FullName);
			var body = caller.Body;
			int at = body.Instructions.IndexOf(call);
			if (at > 0 && body.Instructions[at - 1].OpCode.OpCodeType == OpCodeType.Prefix)
				throw new NotSupportedException("Cannot adapt a prefixed proxy call in " + caller.FullName);
			var inserted = new List<Instruction>();
			var arguments = new Local[helper.MethodSig.Params.Count];
			
			for (int i = arguments.Length - 1; i >= 0; i--)
			{
				arguments[i] = new Local(helper.MethodSig.Params[i]);
				body.Variables.Add(arguments[i]);
				inserted.Add(Instruction.Create(OpCodes.Stloc, arguments[i]));
			}
			for (int i = 0; i < arguments.Length; i++)
			{
				inserted.Add(Instruction.Create(OpCodes.Ldloc, arguments[i]));
				if (NeedsProxyArgumentAdaptation(helper.MethodSig.Params[i], original.MethodSig.Params[i], comparer))
				{
					if (original.MethodSig.Params[i].ElementType == ElementType.Boolean)
					{
						inserted.Add(Instruction.Create(OpCodes.Ldc_I4_0));
						inserted.Add(Instruction.Create(OpCodes.Cgt_Un));
					}
					else inserted.Add(Instruction.Create(OpCodes.Castclass, original.MethodSig.Params[i].ToTypeDefOrRef()));
				}
			}
			Instruction start = inserted[0];
			foreach (var ins in body.Instructions)
			{
				if (ins.Operand == call) ins.Operand = start;
				var targets = ins.Operand as Instruction[];
				if (targets != null) for (int i = 0; i < targets.Length; i++) if (targets[i] == call) targets[i] = start;
			}
			foreach (var eh in body.ExceptionHandlers)
			{
				if (eh.TryStart == call) eh.TryStart = start;
				if (eh.TryEnd == call) eh.TryEnd = start;
				if (eh.HandlerStart == call) eh.HandlerStart = start;
				if (eh.HandlerEnd == call) eh.HandlerEnd = start;
				if (eh.FilterStart == call) eh.FilterStart = start;
			}
			for (int i = 0; i < inserted.Count; i++) body.Instructions.Insert(at + i, inserted[i]);
		}

		private static bool NeedsProxyArgumentAdaptation(TypeSig erased, TypeSig original, SigComparer comparer)
		{
			return !comparer.Equals(erased, original) &&
				!(erased.ElementType == ElementType.U4 && original.ElementType == ElementType.I4);
		}
    }
}
