using System;
using System.IO;

namespace DNGuard_Unpacker
{
	
	internal class LZAri
	{
		
		private int GetBit()
		{
			if ((this.mask >>= 1) == 0U)
			{
				try
				{
					this.buffer = (uint)this.reader.ReadByte();
				}
				catch
				{
					this.buffer = 268435455U;
				}
				this.mask = 128U;
			}
			return Convert.ToInt32((this.buffer & this.mask) != 0U);
		}

		private void StartDecode()
		{
			this.value = 0U;
			for (int i = 0; i < 17; i++)
			{
				this.value = (uint)((ulong)(2U * this.value) + (ulong)((long)this.GetBit()));
			}
		}

		private void StartModel()
		{
			this.sym_cum[314] = 0U;
			for (int num = 314; num >= 1; num--)
			{
				int num2 = num - 1;
				this.char_to_sym[num2] = num;
				this.sym_to_char[num] = num2;
				this.sym_freq[num] = 1U;
				this.sym_cum[num - 1] = this.sym_cum[num] + this.sym_freq[num];
			}
			this.sym_freq[0] = 0U;
			this.position_cum[4096] = 0U;
			for (int num3 = 4096; num3 >= 1; num3--)
			{
				this.position_cum[num3 - 1] = (uint)((ulong)this.position_cum[num3] + (ulong)((long)(10000 / (num3 + 200))));
			}
		}

		private int BinarySearchSym(uint x)
		{
			int num = 1;
			int num2 = 314;
			while (num < num2)
			{
				int num3 = (num + num2) / 2;
				if (this.sym_cum[num3] > x)
				{
					num = num3 + 1;
				}
				else
				{
					num2 = num3;
				}
			}
			return num;
		}

		private void UpdateModel(int sym)
		{
			int num2;
			if (this.sym_cum[0] >= 32767U)
			{
				int num = 0;
				for (num2 = 314; num2 > 0; num2--)
				{
					this.sym_cum[num2] = (uint)num;
					num += (int)(this.sym_freq[num2] = this.sym_freq[num2] + 1U >> 1);
				}
				this.sym_cum[0] = (uint)num;
			}
			num2 = sym;
			while (this.sym_freq[num2] == this.sym_freq[num2 - 1])
			{
				num2--;
			}
			if (num2 < sym)
			{
				int num3 = this.sym_to_char[num2];
				int num4 = this.sym_to_char[sym];
				this.sym_to_char[num2] = num4;
				this.sym_to_char[sym] = num3;
				this.char_to_sym[num3] = sym;
				this.char_to_sym[num4] = num2;
			}
			this.sym_freq[num2] += 1U;
			while (--num2 >= 0)
			{
				this.sym_cum[num2] += 1U;
			}
		}

		private int DecodeChar()
		{
			uint num = this.high - this.low;
			int num2 = this.BinarySearchSym(((this.value - this.low + 1U) * this.sym_cum[0] - 1U) / num);
			this.high = this.low + num * this.sym_cum[num2 - 1] / this.sym_cum[0];
			this.low += num * this.sym_cum[num2] / this.sym_cum[0];
			for (;;)
			{
				if (this.low >= 65536U)
				{
					this.value -= 65536U;
					this.low -= 65536U;
					this.high -= 65536U;
				}
				else if (this.low >= 32768U && this.high <= 98304U)
				{
					this.value -= 32768U;
					this.low -= 32768U;
					this.high -= 32768U;
				}
				else if (this.high > 65536U)
				{
					break;
				}
				this.low += this.low;
				this.high += this.high;
				this.value = (uint)((ulong)(2U * this.value) + (ulong)((long)this.GetBit()));
			}
			int result = this.sym_to_char[num2];
			this.UpdateModel(num2);
			return result;
		}

		private int BinarySearchPos(uint x)
		{
			int num = 1;
			int num2 = 4096;
			while (num < num2)
			{
				int num3 = (num + num2) / 2;
				if (this.position_cum[num3] > x)
				{
					num = num3 + 1;
				}
				else
				{
					num2 = num3;
				}
			}
			return num - 1;
		}

		private int DecodePosition()
		{
			uint num = this.high - this.low;
			int num2 = this.BinarySearchPos(((this.value - this.low + 1U) * this.position_cum[0] - 1U) / num);
			this.high = this.low + num * this.position_cum[num2] / this.position_cum[0];
			this.low += num * this.position_cum[num2 + 1] / this.position_cum[0];
			for (;;)
			{
				if (this.low >= 65536U)
				{
					this.value -= 65536U;
					this.low -= 65536U;
					this.high -= 65536U;
				}
				else if (this.low >= 32768U && this.high <= 98304U)
				{
					this.value -= 32768U;
					this.low -= 32768U;
					this.high -= 32768U;
				}
				else if (this.high > 65536U)
				{
					break;
				}
				this.low += this.low;
				this.high += this.high;
				this.value = (uint)((ulong)(2U * this.value) + (ulong)((long)this.GetBit()));
			}
			return num2;
		}

		public byte[] Decode(byte[] encoded)
		{
			this.in_stream = new MemoryStream(encoded);
			BinaryWriter binaryWriter = new BinaryWriter(this.out_stream);
			this.reader = new BinaryReader(this.in_stream);
			byte[] array = new byte[4155];
			int num = this.reader.ReadInt32();
			if (num < 1 || num > 64 * 1024 * 1024)
			{
				throw new InvalidDataException("LZAri output length is outside the 1..64 MiB limit.");
			}
			byte[] array2;
			if (encoded.Length == 0)
			{
				array2 = null;
			}
			else
			{
				this.StartDecode();
				this.StartModel();
				for (int i = 0; i < 4036; i++)
				{
					array[i] = 32;
				}
				int num2 = 4036;
				uint num3 = 0U;
				while ((ulong)num3 < (ulong)((long)num))
				{
					int num4 = this.DecodeChar();
					if (num4 < 256)
					{
						binaryWriter.Write((byte)num4);
						array[num2++] = (byte)num4;
						num2 &= 4095;
						num3 += 1U;
					}
					else
					{
						int i = (num2 - this.DecodePosition() - 1) & 4095;
						int num5 = num4 - 255 + 2;
						for (int j = 0; j < num5; j++)
						{
							num4 = (int)array[(i + j) & 4095];
							binaryWriter.Write((byte)num4);
							array[num2++] = (byte)num4;
							num2 &= 4095;
							num3 += 1U;
						}
					}
				}
				byte[] result = this.out_stream.ToArray();
				this.out_stream.Flush();
				this.in_stream.Flush();
				binaryWriter.Flush();
				array2 = result;
			}
			return array2;
		}

		private MemoryStream in_stream;

		private MemoryStream out_stream = new MemoryStream();

		private BinaryReader reader;

		private uint low = 0U;

		private uint high = 131072U;

		private uint value = 0U;

		private int[] char_to_sym = new int[314];

		private int[] sym_to_char = new int[315];

		private uint[] sym_freq = new uint[315];

		private uint[] sym_cum = new uint[315];

		private uint[] position_cum = new uint[4097];

		private uint buffer = 0U;

		private uint mask = 0U;

		internal static class LZConstants
		{
			
			public const int N = 4096;

			public const int F = 60;

			public const int THRESHOLD = 2;

			public const int M = 15;

			public const int Q1 = 32768;

			public const int Q2 = 65536;

			public const int Q3 = 98304;

			public const int Q4 = 131072;

			public const int MAX_CUM = 32767;
		}
	}
}
