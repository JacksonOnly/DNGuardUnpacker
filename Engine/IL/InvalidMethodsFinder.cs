using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DNGuard_Unpacker
{
	
	internal class InvalidMethodsFinder
	{
		
		public static void Remove(ModuleDef module)
		{
			foreach (MethodDef invalidMethod in InvalidMethodsFinder.FindAll(module))
			{
				invalidMethod.DeclaringType.Remove(invalidMethod);
			}
		}

		public static List<MethodDef> FindAll(ModuleDef module)
		{
			List<MethodDef> list = new List<MethodDef>();
			foreach (TypeDef typeDef in module.GetTypes())
			{
				foreach (MethodDef methodDef in typeDef.Methods)
				{
					if (InvalidMethodsFinder.IsInvalidMethod(methodDef))
					{
						list.Add(methodDef);
					}
				}
			}
			return list;
		}

        public static int RemoveUnreferenced(ModuleDef module)
        {
                List<MethodDef> invalid = FindAll(module);
                if (invalid.Count == 0) return 0;
                HashSet<MethodDef> referenced = new HashSet<MethodDef>();
                Action<IMethod> keep = method => { if (method != null) { MethodDef definition = method.ResolveMethodDef(); if (definition != null) referenced.Add(definition); } };
                keep(module.EntryPoint);
                foreach (TypeDef type in module.GetTypes())
                {
                        foreach (var attribute in type.CustomAttributes) keep(attribute.Constructor as IMethod);
                        foreach (PropertyDef property in type.Properties)
                                foreach (MethodDef accessor in property.GetMethods.Concat(property.SetMethods).Concat(property.OtherMethods)) keep(accessor);
                        foreach (EventDef @event in type.Events)
                        {
                                keep(@event.AddMethod); keep(@event.RemoveMethod); keep(@event.InvokeMethod);
                                foreach (MethodDef other in @event.OtherMethods) keep(other);
                        }
                        foreach (MethodDef method in type.Methods)
                        {
                                foreach (var attribute in method.CustomAttributes) keep(attribute.Constructor as IMethod);
                                if (!method.HasBody) continue;
                                foreach (Instruction instruction in method.Body.Instructions) keep(instruction.Operand as IMethod);
                        }
                }
                int removed = 0;
                foreach (MethodDef method in invalid)
                        if (!referenced.Contains(method)) { method.DeclaringType.Remove(method); removed++; }
                return removed;
        }

		public static bool IsInvalidMethod(MethodDef method)
		{
			bool flag;
			if (method == null)
			{
				flag = false;
			}
			else if (!method.HasBody)
			{
				flag = false;
			}
			else
			{
				foreach (Instruction instruction in method.Body.Instructions)
				{
					if (instruction.OpCode.Code == Code.Ldstr)
					{
						string str = (string)instruction.Operand;
						if (str == "\u9B47" || str == "\u5BE0" || str == "Error, DNGuard Runtime library not loaded!")
						{
							return true;
						}
					}
				}
				flag = false;
			}
			return flag;
		}
	}
}
