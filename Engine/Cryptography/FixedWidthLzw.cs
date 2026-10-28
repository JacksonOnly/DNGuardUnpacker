using System;
using System.Collections.Generic;
using System.IO;

namespace DNGuard_Unpacker
{
    internal static class FixedWidthLzw
    {
        public static byte[] Decode(byte[] input)
        {
            if (input.Length < 5) throw new InvalidDataException("LZW 数据头不完整。");
            int expected = BitConverter.ToInt32(input, 0), width = input[4];
            if (expected < 0 || expected > 64 * 1024 * 1024 || width < 9 || width > 16)
                throw new InvalidDataException("LZW 长度或位宽无效。");
            var dictionary = new List<byte[]>(1 << width);
            for (int i = 0; i < 256; i++) dictionary.Add(new[] { (byte)i });
            using (var output = new MemoryStream(expected))
            {
                long bit = 40;
                byte[] previous = null;
                while (output.Length < expected)
                {
                    if (bit + width > (long)input.Length * 8) throw new InvalidDataException("LZW 数据被截断。");
                    int code = 0;
                    for (int j = 0; j < width; j++, bit++) code |= ((input[bit >> 3] >> (int)(bit & 7)) & 1) << j;
                    byte[] entry;
                    if (code < dictionary.Count) entry = dictionary[code];
                    else if (code == dictionary.Count && previous != null) entry = Append(previous, previous[0]);
                    else throw new InvalidDataException("LZW 字典编号无效。");
                    if (output.Length + entry.Length > expected) throw new InvalidDataException("LZW 解压长度不一致。");
                    output.Write(entry, 0, entry.Length);
                    if (previous != null && dictionary.Count < (1 << width)) dictionary.Add(Append(previous, entry[0]));
                    previous = entry;
                }
                return output.ToArray();
            }
        }

        private static byte[] Append(byte[] prefix, byte value)
        {
            var result = new byte[prefix.Length + 1];
            Buffer.BlockCopy(prefix, 0, result, 0, prefix.Length);
            result[prefix.Length] = value;
            return result;
        }
    }
}
