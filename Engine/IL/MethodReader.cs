using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.IO;

namespace DNGuard_Unpacker
{
	
	internal class MethodReader : MethodBodyReaderBase
	{
		
		public MethodReader(ModuleDefMD module, MethodsDecrypter.DecrypterBase.methodInfo mi, IList<Parameter> parameters, MethodsDecrypter.DecrypterBase db)
			: base(ByteArrayDataReaderFactory.CreateReader(mi.MethodData), parameters)
		{
			this.module = module;
			this.ehBytes = mi.MethodEH;
			if (mi.MethodEH != null)
			{
				this.ehReader = ByteArrayDataReaderFactory.CreateReader(mi.MethodEH);
			}
			this.localsArray = null;
			foreach (Local item in mi.Method_Locals)
			{
				base.Locals.Add(item);
			}
			this.decryptor = db;
			this.methodInfo = mi;
		}

		protected override MethodSig ReadInlineSig(Instruction instr)
		{
			uint token = this.reader.ReadUInt32();
			MethodSig result;
			if (MDToken.ToTable(token) != Table.StandAloneSig)
			{
				result = null;
			}
			else
			{
				StandAloneSig standAloneSig = this.module.ResolveStandAloneSig(MDToken.ToRID(token), this.gpContext);
				result = ((standAloneSig != null) ? standAloneSig.MethodSig : null);
			}
			return result;
		}

		public void Read(MethodDef method)
		{
			this.gpContext = GenericParamContext.Create(method);
			if (this.localsArray != null)
			{
				LocalSig localSig = (LocalSig)SignatureReader.ReadSig(this.module, this.localsArray);
				if (localSig != null)
				{
					base.SetLocals(localSig.GetLocals());
				}
			}
			base.ReadInstructions((int)this.reader.Length);
			if (this.ehBytes != null)
			{
				this.ReadExceptionHandlers(this.ehReader);
			}
		}

		private T Resolve<T>(int token)
		{
			return (T)((object)this.module.ResolveToken(token, this.gpContext));
		}

		protected override ITokenOperand ReadInlineTok(Instruction instr)
		{
			uint token = (uint)this.reader.ReadInt32();
			if (this.decryptor.UsesEncodedMetadataTokens)
			{
				token = this.decryptor.DecryptHVMToken(token, this.hvm_counter, this.methodInfo);
				this.hvm_counter++;
			}
			return this.Resolve<ITokenOperand>((int)token);
		}

		protected override string ReadInlineString(Instruction instr)
		{
			uint token = (uint)this.reader.ReadInt32();
			if (this.decryptor.UsesEncodedMetadataTokens)
			{
				token = this.decryptor.DecryptHVMToken(token, this.hvm_counter, this.methodInfo);
				this.hvm_counter++;
			}
			return this.decryptor.ReadInlineUserString(token);
		}

		protected override ITypeDefOrRef ReadInlineType(Instruction instr)
		{
			uint token = (uint)this.reader.ReadInt32();
			if (this.decryptor.UsesEncodedMetadataTokens)
			{
				token = this.decryptor.DecryptHVMToken(token, this.hvm_counter, this.methodInfo);
				this.hvm_counter++;
			}
			return this.Resolve<ITypeDefOrRef>((int)token);
		}

		protected override IField ReadInlineField(Instruction instr)
		{
			uint token = (uint)this.reader.ReadInt32();
			if (this.decryptor.UsesEncodedMetadataTokens)
			{
				token = this.decryptor.DecryptHVMToken(token, this.hvm_counter, this.methodInfo);
				this.hvm_counter++;
			}
			return this.Resolve<IField>((int)token);
		}

		protected override IMethod ReadInlineMethod(Instruction instr)
		{
			uint token = (uint)this.reader.ReadInt32();
			if (this.decryptor.UsesEncodedMetadataTokens)
			{
				token = this.decryptor.DecryptHVMToken(token, this.hvm_counter, this.methodInfo);
				this.hvm_counter++;
			}
			return this.Resolve<IMethod>((int)token);
		}

		private void ReadExceptionHandlers(DataReader ehReader)
		{
			byte b = ehReader.ReadByte();
			bool IsFat = (b & 64) > 0;
			if (IsFat)
			{
				this.ReadFatExceptionHandlers(ref ehReader);
			}
			else if ((b & 63) == 1)
			{
				this.ReadSmallExceptionHandlers(ref ehReader);
			}
		}

		private static ushort GetNumberOfExceptionHandlers(uint num)
		{
			return (ushort)num;
		}

		private void ReadFatExceptionHandlers(ref DataReader ehReader)
		{
			uint position = ehReader.Position;
			ehReader.Position = position - 1U;
			int numberOfExceptionHandlers = (int)MethodReader.GetNumberOfExceptionHandlers((ehReader.ReadUInt32() >> 8) / 24U);
			for (int i = 0; i < numberOfExceptionHandlers; i++)
			{
				ExceptionHandler exceptionHandler = new ExceptionHandler((ExceptionHandlerType)ehReader.ReadUInt32());
				uint offset = ehReader.ReadUInt32();
				exceptionHandler.TryStart = base.GetInstruction(offset);
				exceptionHandler.TryEnd = base.GetInstruction(offset + ehReader.ReadUInt32());
				offset = ehReader.ReadUInt32();
				exceptionHandler.HandlerStart = base.GetInstruction(offset);
				exceptionHandler.HandlerEnd = base.GetInstruction(offset + ehReader.ReadUInt32());
				if (exceptionHandler.HandlerType == ExceptionHandlerType.Catch)
				{
					exceptionHandler.CatchType = this.module.ResolveToken(ehReader.ReadUInt32(), this.gpContext) as ITypeDefOrRef;
				}
				else if (exceptionHandler.HandlerType == ExceptionHandlerType.Filter)
				{
					exceptionHandler.FilterStart = base.GetInstruction(ehReader.ReadUInt32());
				}
				else
				{
					ehReader.ReadUInt32();
				}
				base.Add(exceptionHandler);
			}
		}

		private void ReadSmallExceptionHandlers(ref DataReader ehReader)
		{
			int numberOfExceptionHandlers = (int)MethodReader.GetNumberOfExceptionHandlers((uint)(ehReader.ReadByte() / 12));
			ehReader.Position += 2U;
			for (int i = 0; i < numberOfExceptionHandlers; i++)
			{
				ExceptionHandler exceptionHandler = new ExceptionHandler((ExceptionHandlerType)ehReader.ReadUInt16());
				uint num = (uint)ehReader.ReadUInt16();
				exceptionHandler.TryStart = base.GetInstruction(num);
				exceptionHandler.TryEnd = base.GetInstruction(num + (uint)ehReader.ReadByte());
				num = (uint)ehReader.ReadUInt16();
				exceptionHandler.HandlerStart = base.GetInstruction(num);
				exceptionHandler.HandlerEnd = base.GetInstruction(num + (uint)ehReader.ReadByte());
				if (exceptionHandler.HandlerType == ExceptionHandlerType.Catch)
				{
					exceptionHandler.CatchType = this.module.ResolveToken(ehReader.ReadUInt32(), this.gpContext) as ITypeDefOrRef;
				}
				else if (exceptionHandler.HandlerType == ExceptionHandlerType.Filter)
				{
					exceptionHandler.FilterStart = base.GetInstruction(ehReader.ReadUInt32());
				}
				else
				{
					ehReader.ReadUInt32();
				}
				base.Add(exceptionHandler);
			}
		}

		private ModuleDefMD module;

		private GenericParamContext gpContext;

		private MethodsDecrypter.DecrypterBase decryptor;

		private MethodsDecrypter.DecrypterBase.methodInfo methodInfo;

		private int hvm_counter = 1;

		private readonly byte[] ehBytes;

		private readonly DataReader ehReader;

		private readonly byte[] localsArray;
	}
}
