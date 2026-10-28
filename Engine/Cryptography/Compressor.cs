using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DNGuard_Unpacker
{
	
	public static class Compressor
	{

        
        
        internal static byte[] DecompressEntry(byte[] buffer)
        {
            if (buffer == null || buffer.Length < 10) throw new InvalidDataException("Truncated bundled Huffman entry.");
            uint size = BitConverter.ToUInt32(buffer, 0);
            int count = buffer[4] + 1, header = 5 + count * 5;
            if (size == 0 || size > 64 * 1024 * 1024 || header > buffer.Length)
                throw new InvalidDataException("Invalid bundled Huffman entry size.");
            var symbols = new List<CompressorStruct>();
            var frequencies = new uint[256];
            ulong total = 0;
            uint previous = uint.MaxValue;
            for (int i = 0; i < count; i++)
            {
                uint frequency = BitConverter.ToUInt32(buffer, 5 + i * 5);
                byte symbol = buffer[9 + i * 5];
                if (frequency == 0 || frequency > previous || frequencies[symbol] != 0)
                    throw new InvalidDataException("Invalid bundled Huffman frequency table.");
                frequencies[symbol] = frequency;
                previous = frequency;
                total += frequency;
                symbols.Add(new CompressorStruct(frequency, symbol));
            }
            if (total != size) throw new InvalidDataException("Bundled Huffman frequency sum mismatch.");
            var table = BuildCompressorTable(symbols);
            var output = new byte[checked((int)size)];
            long bit = (long)header * 8;
            for (int i = 0; i < output.Length; i++)
            {
                int node = table.Length - 1;
                while (table[node].C2 != -1)
                {
                    if (bit >= (long)buffer.Length * 8) throw new InvalidDataException("Truncated bundled Huffman bitstream.");
                    node = ((buffer[bit >> 3] >> (int)(bit & 7)) & 1) == 0 ? table[node].C2 : table[node].C3;
                    bit++;
                }
                byte symbol = table[node].b;
                if (frequencies[symbol] == 0) throw new InvalidDataException("Bundled Huffman decoded frequency mismatch.");
                frequencies[symbol]--;
                output[i] = symbol;
            }
            if (frequencies.Any(f => f != 0)) throw new InvalidDataException("Bundled Huffman decoded frequency mismatch.");
            return output;
        }
		
		public static byte[] Decompress(byte[] buffer)
		{
			List<byte> list = new List<byte>();
			using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(buffer)))
			{
				uint num = binaryReader.ReadUInt32();
				byte b = binaryReader.ReadByte();
				List<Compressor.CompressorStruct> list2 = new List<Compressor.CompressorStruct>();
				for (int i = 0; i <= (int)b; i++)
				{
					list2.Add(new Compressor.CompressorStruct(binaryReader.ReadUInt32(), binaryReader.ReadByte()));
				}
				int num2 = (int)binaryReader.BaseStream.Position;
				byte[] array = binaryReader.ReadBytes(buffer.Length - (int)((b + 2) * 5));
				Array.Resize<byte>(ref array, array.Length + 3);
				Compressor.CompressorStruct[] array2 = Compressor.BuildCompressorTable(list2);
				int num3 = (int)((b + 2) * 5 * 8);
				int j = 0;
				while ((long)j < (long)((ulong)num))
				{
					int num4 = num3 >> 3;
					num4 -= num2;
					uint num5 = BitConverter.ToUInt32(array, num4);
					num5 >>= num3 & 7;
					int num6 = array2.Length - 1;
					while (array2[num6].C2 != -1)
					{
						Compressor.CompressorStruct compressorStruct = array2[num6];
						num6 = (((num5 & 1U) == 0U) ? compressorStruct.C2 : compressorStruct.C3);
						num5 >>= 1;
						num3++;
					}
					list.Add(array2[num6].b);
					j++;
				}
			}
			return list.ToArray();
		}

		private static Compressor.CompressorStruct[] BuildCompressorTable(List<Compressor.CompressorStruct> Table)
		{
			List<Compressor.CompressorStruct> list = Table;
			if (Table.Count - 1 > 0)
			{
				for (int num = list.Count - 1; num > 0; num++)
				{
					Compressor.CompressorStruct compressorStruct = default(Compressor.CompressorStruct).Create();
					Compressor.CompressorStruct compressorStruct2 = default(Compressor.CompressorStruct).Create();
					Compressor.CompressorStruct compressorStruct3 = default(Compressor.CompressorStruct).Create();
					Compressor.CompressorStruct compressorStruct4 = default(Compressor.CompressorStruct).Create();
					compressorStruct3 = list[num];
					compressorStruct.C2 = Table.IndexOf(compressorStruct3);
					num--;
					compressorStruct4 = list[num];
					compressorStruct.C3 = Table.IndexOf(compressorStruct4);
					num--;
					compressorStruct.Count = compressorStruct3.Count + compressorStruct4.Count;
					Table.Add(compressorStruct);
					int num2 = num;
					while (num2 > -1 && list[num2].Count < compressorStruct.Count)
					{
						num2--;
					}
					int length = num - num2;
					compressorStruct2 = list[num2 + 1];
					compressorStruct3 = list[num2 + 2];
					Compressor.CompressorStruct[] array = list.ToArray();
					Array.Copy(array, list.IndexOf(compressorStruct2), array, list.IndexOf(compressorStruct3), length);
					list = new List<Compressor.CompressorStruct>(array);
					list[list.IndexOf(compressorStruct2)] = compressorStruct;
				}
			}
			return Table.ToArray();
		}

		private struct CompressorStruct
		{
			
			public Compressor.CompressorStruct Create()
			{
				Compressor.CompressorStruct result = default(Compressor.CompressorStruct);
				result.C2 = (result.C3 = -1);
				return result;
			}

			public CompressorStruct(uint Count, byte b)
			{
				this.Count = Count;
				this.b = b;
				this.C2 = (this.C3 = -1);
			}

			public uint Count;

			public readonly byte b;

			public int C2;

			public int C3;
		}
	}
}
