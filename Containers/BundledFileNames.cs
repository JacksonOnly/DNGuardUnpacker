using System;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Xml;
using dnlib.DotNet;
using dnlib.PE;
using dnlib.IO;

namespace DNGuard_Unpacker
{
    
    internal static class BundledFileNames
    {
        internal static string Read(byte[] bytes, string applicationName)
        {
            string name;
            if (bytes.Length >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A)
            {
                using (var pe = new PEImage(bytes))
                {
                    if (pe.ImageNTHeaders.OptionalHeader.DataDirectories[14].VirtualAddress != 0)
                    {
                        using (var module = ModuleDefMD.Load(bytes))
                        {
                            if (module.Assembly == null) throw new InvalidDataException("Bundled managed file has no assembly identity.");
                            name = module.Name.String;
                        }
                    }
                    else
                    {
                        if (((ushort)pe.ImageNTHeaders.FileHeader.Characteristics & 0x2000) == 0)
                            throw new InvalidDataException("Unnamed native executable in bundle.");
                        uint exportRva = (uint)pe.ImageNTHeaders.OptionalHeader.DataDirectories[0].VirtualAddress;
                        int export = Raw(pe, bytes, exportRva, 40);
                        int start = Raw(pe, bytes, BitConverter.ToUInt32(bytes, export + 12), 1), end = start;
                        while (end < bytes.Length && end - start < 260 && bytes[end] != 0) end++;
                        if (end == bytes.Length || end - start >= 260) throw new InvalidDataException("Invalid bundled DLL export name.");
                        name = Encoding.ASCII.GetString(bytes, start, end - start);
                    }
                }
                if (!name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Bundled PE name lacks a supported extension.");
            }
            else
            {
                var document = new XmlDocument { XmlResolver = null };
                try
                {
                    using (var reader = JsonReaderWriterFactory.CreateJsonReader(bytes, XmlDictionaryReaderQuotas.Max))
                        document.Load(reader);
                }
                catch (XmlException error) { throw new InvalidDataException("Unknown non-PE bundled file.", error); }
                var root = document.DocumentElement;
                if (root != null && root["runtimeTarget"] != null && root["targets"] != null && root["libraries"] != null)
                    name = applicationName + ".deps.json";
                else if (root != null && root["runtimeOptions"] != null)
                    name = applicationName + ".runtimeconfig.json";
                else throw new InvalidDataException("Unrecognized bundled JSON document.");
            }
            Validate(name);
            return name;
        }

        internal static void Validate(string name)
        {
            if (string.IsNullOrWhiteSpace(name) || name != Path.GetFileName(name) ||
                name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name.EndsWith(".") || name.EndsWith(" ") ||
                System.Text.RegularExpressions.Regex.IsMatch(name, @"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                throw new InvalidDataException("Unsafe bundled file name: " + name);
        }

        private static int Raw(IPEImage pe, byte[] bytes, uint rva, int size)
        {
            uint raw = (uint)pe.ToFileOffset((RVA)rva);
            if (rva == 0 || raw == 0 || (uint)pe.ToRVA((FileOffset)raw) != rva || (ulong)raw + (uint)size > (ulong)bytes.Length)
                throw new InvalidDataException("Bundled DLL export data is outside its PE image.");
            return checked((int)raw);
        }
    }
}
