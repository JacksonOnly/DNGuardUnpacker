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
        private static void Inspect(ModuleDefMD mod, byte[] bytes)
        {
            Console.WriteLine("INPUT sha256=" + Hash(bytes));
            Console.WriteLine("MODULE " + mod.Name + " methods=" + mod.GetTypes().Sum(t => t.Methods.Count));
            Console.WriteLine("RESOURCES " + string.Join(",", mod.Resources.Select(r => r.Name.String)));
            foreach (var section in mod.Metadata.PEImage.ImageSectionHeaders)
                Console.WriteLine("SECTION " + section.DisplayName + " RVA=" + ((uint)section.VirtualAddress).ToString("X8") + " RAW=" + section.PointerToRawData.ToString("X8") + " SIZE=" + section.SizeOfRawData);
            foreach (var m in mod.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasImplMap))
                Console.WriteLine("IMPORT " + m.FullName + " " + m.ImplMap.Module.Name);
            for (int i = 0; i <= bytes.Length - 180; i++)
            {
                if (bytes[i] != 43 || bytes[i+1] != 7 || (bytes[i+2] != 115 && bytes[i+2] != 32 && bytes[i+2] != 40) ||
                    (bytes[i+7] != 43 && bytes[i+7] != 45) || bytes[i+8] != 7 || (bytes[i+9] != 114 && bytes[i+9] != 32)) continue;
                Console.WriteLine("STRUCT RAW=" + (i + 25).ToString("X8"));
                for (int n = 0; n < 40; n++) Console.WriteLine("  W" + n.ToString("D2") + "=" + BitConverter.ToUInt32(bytes, i+25+n*4).ToString("X8"));
                break;
            }
        }
    }
}
