using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {

        public bool TryCalculateLegacy112MaxStack(MethodDef method, out uint maxStack)
        {
            maxStack = 0;
            if (!this.legacy112Layout || method == null || !method.HasBody) return false;
            var instructions = method.Body.Instructions;
            if (instructions.Count == 0) return false;
            var positions = new Dictionary<Instruction, int>();
            for (int i = 0; i < instructions.Count; i++)
                if (instructions[i] == null || positions.ContainsKey(instructions[i])) return false;
                else positions.Add(instructions[i], i);
            var pending = new Queue<KeyValuePair<int, int>>();
            pending.Enqueue(new KeyValuePair<int, int>(0, 0));
            foreach (var eh in method.Body.ExceptionHandlers)
            {
                int start;
                if (eh.TryStart == null || eh.HandlerStart == null ||
                    !positions.ContainsKey(eh.TryStart) || !positions.TryGetValue(eh.HandlerStart, out start) ||
                    (eh.TryEnd != null && !positions.ContainsKey(eh.TryEnd)) ||
                    (eh.HandlerEnd != null && !positions.ContainsKey(eh.HandlerEnd))) return false;
                pending.Enqueue(new KeyValuePair<int, int>(start,
                    eh.HandlerType == ExceptionHandlerType.Catch || eh.HandlerType == ExceptionHandlerType.Filter ? 1 : 0));
                if (eh.FilterStart != null)
                {
                    if (!positions.TryGetValue(eh.FilterStart, out start)) return false;
                    pending.Enqueue(new KeyValuePair<int, int>(start, 1));
                }
            }
            var heights = new Dictionary<int, int>();

            bool hasReturn = method.MethodSig.RetType.RemovePinnedAndModifiers().ElementType != ElementType.Void;
            while (pending.Count != 0)
            {
                var next = pending.Dequeue();
                int index = next.Key, height = next.Value, existing;
                if (heights.TryGetValue(index, out existing))
                {
                    if (height != existing) return false;
                    continue;
                }
                heights.Add(index, height);
                maxStack = Math.Max(maxStack, (uint)height);
                var instruction = instructions[index];
                int pushes, pops;
                instruction.CalculateStackUsage(hasReturn, out pushes, out pops);
                if (instruction.OpCode.Code == Code.Ret)
                {
                    if (height != (hasReturn ? 1 : 0)) return false;
                    continue;
                }
                if (instruction.OpCode.Code == Code.Endfinally && height != 0) return false;
                if (pops < 0) height = 0;
                else
                {
                    if (height < pops || pushes < 0) return false;
                    height = checked(height - pops + pushes);
                }
                if (height > ushort.MaxValue) return false;
                maxStack = Math.Max(maxStack, (uint)height);
                int target;
                if (instruction.Operand is Instruction branch)
                {
                    if (!positions.TryGetValue(branch, out target)) return false;
                    pending.Enqueue(new KeyValuePair<int, int>(target, height));
                }
                else if (instruction.Operand is IList<Instruction> branches)
                    foreach (var entry in branches)
                    {
                        if (entry == null || !positions.TryGetValue(entry, out target)) return false;
                        pending.Enqueue(new KeyValuePair<int, int>(target, height));
                    }
                var flow = instruction.OpCode.FlowControl;
                if (flow == FlowControl.Return && height != 0) return false;
                if (flow == FlowControl.Branch || flow == FlowControl.Return || flow == FlowControl.Throw) continue;
                if (index + 1 == instructions.Count) return false;
                pending.Enqueue(new KeyValuePair<int, int>(index + 1, height));
            }
            return true;
        }
    }
}
