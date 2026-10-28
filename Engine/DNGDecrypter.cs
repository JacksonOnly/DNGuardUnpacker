using DNGuard_Unpacker.Versions;
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

namespace DNGuard_Unpacker
{
	public partial class DNGDecrypter : MethodsDecrypter.DecrypterBase
	{
		private bool modernLayout;
        private bool requireValidatedRuntimeMethods;
        internal void RequireValidatedRuntimeMethods() { this.requireValidatedRuntimeMethods = true; }
        private bool suppressLayoutLog;
                public bool IsModernLayout { get { return this.modernLayout; } }
        
        public bool IsLegacy112Layout { get { return this.legacy112Layout; } }
        protected override bool PreserveMethodImplAttributes { get { return this.legacy112Layout; } }
		private bool modernLehLengthFirst;

		private int modernFamily;
        private ModernVersionProfile Profile => ModernVersionRegistry.Profiles[modernFamily];
		private byte[] externalMethods;
		private readonly HashSet<uint> modernFakeMethods = new HashSet<uint>();
		public DNGDecrypter(ModuleDefMD module, byte[] externalMethods = null)
			: base(module)
		{
			this.externalMethods = externalMethods;
		}
		public int GetStructSize(int size, ref byte[] array)
		{
			this.reader.Position = this.DataOffset;
			array = this.reader.ReadBytes(size);
			uint[] dst = new uint[array.Length / 4];
			Buffer.BlockCopy(array, 0, dst, 0, array.Length);
			Adler32 adler = new Adler32();
			adler.Update(array);
			int num;
			if ((ulong)this.MetaDataValue[2] == (ulong)adler.Value)
			{
				num = size;
			}
			else
			{
				num = 0;
			}
			return num;
		}
		public void PrintInformation()
		{
			Console.WriteLine("Value1=" + DNGDecrypter.GetHexBytes(this.value1) + " Value3=" + DNGDecrypter.GetHexBytes(this.value3));
			Console.WriteLine("ProtectionSettings=" + this.DataStructure.ProtectionSettings.ToString("X8"));
			if ((this.DataStructure.ProtectionSettings & 512U) != 0U)
			{
				Console.WriteLine("Avoid ilegal jit action is enabled!");
			}
			else
			{
				Console.WriteLine("Avoid ilegal jit action is disabled!");
			}
			Console.WriteLine("ProtectionFeatures=" + this.DataStructure.ProtectionFeatures.ToString());
			bool isEnterprise = base.IsHVMTechnologyEnabled();
			Console.WriteLine("- Version: " + (isEnterprise ? "Enterprise" : "Professional"));
		}
		public static string GetHexBytes(uint value1)
		{
			byte[] bytes = BitConverter.GetBytes(value1);
			return BitConverter.ToString(bytes).Replace("-", string.Empty);
		}
		public static uint GetMaximProtectSettings()
		{
			return 4067U;
		}
		public static int CountBits(uint value)
		{
			int count = 0;
			while (value != 0U)
			{
				count++;
				value &= value - 1U;
			}
			return count;
		}

		private void ValidateMethodDataBounds()
		{
			if (this.externalMethods != null)
			{
				if (!IsExternalBlockLayout(this.DataStructure.MethodsBufferLength, this.DataStructure.LEHSize))
					throw new InvalidDataException("Invalid external modern method block.");
				return;
			}
			ulong imageLength = this.reader.Length;
			ulong tableLength = (ulong)this.DataStructure.MethodsCount * 4UL;
			ulong bufferLength = this.DataStructure.MethodsBufferLength;
			if (this.DataStructure.MethodsCount == 0U || tableLength > int.MaxValue ||
				bufferLength == 0UL || bufferLength > int.MaxValue)
			{
				throw new InvalidDataException("Invalid DNGuard methods count or buffer length; the structure layout may be unsupported.");
			}
			ulong methodsOffset = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.MethodsDataOffset);
			bool contiguousLeh = this.modernLayout || this.ContiguousLegacyLeh;
			ulong methodsLength = tableLength + bufferLength + (contiguousLeh ? this.DataStructure.LEHSize : 0UL);
            if (methodsOffset == 0 || (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)(uint)methodsOffset) != this.DataStructure.MethodsDataOffset || methodsOffset >= imageLength || methodsLength > imageLength - methodsOffset)
			{
				throw new InvalidDataException(string.Format(
					"DNGuard method data is outside the module (RVA 0x{0:X8}, count {1}, buffer {2}, file size {3}); the structure layout or extracted module may be incomplete.",
					this.DataStructure.MethodsDataOffset, this.DataStructure.MethodsCount,
					this.DataStructure.MethodsBufferLength, imageLength));
			}
			if (!contiguousLeh && this.DataStructure.LEHSize > 0U)
			{
				ulong lehOffset = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.LocalsAndEHOffset);
                if (lehOffset == 0 || (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)(uint)lehOffset) != this.DataStructure.LocalsAndEHOffset || lehOffset >= imageLength || (ulong)this.DataStructure.LEHSize > imageLength - lehOffset)
				{
					throw new InvalidDataException("DNGuard exception handler data is outside the module; the structure layout or extracted module may be incomplete.");
				}
			}
		}

		public int StructSize = 0;
		private LegacyLayoutKind legacyLayout;
        public string LayoutName => this.modernLayout ? Profile.GetType().Name : this.legacyLayout.ToString();
		public static uint[] ivalues;
		private uint value1;
		private uint value2;
		private uint value3;
		private uint valueN4;
		private uint valueN5;
		private Blowfish blowfishInstance;
		private byte[] algoKey;
		private uint UncompressedMethodsBufferLength;
		private uint LEHLocalsOffset;
		private uint HvmTokenTableOffset;
		private uint HvmTokenTableSize;
		private byte[] HvmTable;
		public static uint[] tokenBases = new uint[] { 452984832U, 16777216U, 33554432U, 167772160U, 67108864U, 167772160U, 100663296U, 721420288U, 1879048192U, 285212672U };
	}
}
