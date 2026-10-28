using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.IO;
using dnlib.PE;

namespace DNGuard_Unpacker
{
	
	public partial class MethodsDecrypter
	{

		public bool Detected
		{
			get
			{
				return this.foundRtType || this.DNGRtType != null;
			}
		}

		public MethodDef InitializeMethod
		{
			get
			{
				return this.initializeMethod;
			}
		}

		public TypeDef RTType
		{
			get
			{
				return this.DNGRtType;
			}
		}

		public string Version
		{
			get
			{
                return (this.decrypter as DNGDecrypter)?.LayoutName;
			}
		}

		private readonly byte[] externalMethods;
		public MethodsDecrypter(ModuleDefMD module, byte[] externalMethods = null)
		{
			this.module = module;
			this.externalMethods = externalMethods;
		}

		public void DecryptInternal(ref byte[] fileData)
		{
			if (this.decrypter != null)
			{
				this.decrypter.DecryptInternal(ref fileData);
			}
		}

		public void Decrypt()
		{
			if (this.decrypter != null)
			{
				this.decrypter.ReadMethods();
				this.decrypter.RestoreMethods();
			}
		}

		public void Find()
		{
			string typeName = "NETShieldRT";
			foreach (TypeDef typeDef in this.module.GetTypes())
			{
				if (typeDef.FullName.Contains("ZYXDNGuarder"))
				{
					this.DNGRtType = typeDef;
					foreach (MethodDef method in typeDef.Methods)
					{
						if (method.Name == "Startup" || method.Name == "Execute")
						{
							this.initializeMethod = method;
							this.foundRtType = true;
						}
						bool flag2 = method.FullName.Contains("ZYXDNGuarder::CheckRuntime()") || method.FullName.Contains("ZYXDNGuarder::CheckRuntime(System.Int32)");
						if (flag2)
						{
							bool hasImplMap = method.HasImplMap;
							if (hasImplMap)
							{
								string NativeModuleName = method.ImplMap.Module.Name;
								string directoryName;
								if (this.module.Location == null || this.module.Location == "")
								{
									directoryName = Path.GetDirectoryName(Program.path);
								}
								else
								{
									directoryName = Path.GetDirectoryName(this.module.Location);
								}
								if (directoryName == null)
								{
									throw new InvalidOperationException("Invalid path");
								}
								MethodsDecrypter.NativeModulePath32 = Path.Combine(directoryName, NativeModuleName);
								this.foundRtType = true;
							}
						}
					}
				}
				if (typeDef.FullName.Contains(typeName))
				{
					this.DNGRtType = typeDef;
					foreach (MethodDef methodDef in typeDef.Methods)
					{
						if (methodDef.FullName.Contains(typeName + "::Startup()") || methodDef.FullName.Contains(typeName + "::Execute()"))
						{
							this.initializeMethod = methodDef;
							this.foundRtType = true;
						}
					}
				}
			}
			this.decrypter = new DNGDecrypter(this.module, this.externalMethods);
			if (this.decrypter != null)
			{
				this.decrypter.ParseStructure();
			}
            if (this.DNGRtType == null) this.FindRenamedRuntime();
		}

		public static string NativeModulePath32 = string.Empty;

		private ModuleDefMD module;

		public IDecrypter decrypter;

		private TypeDef DNGRtType;

		private MethodDef initializeMethod;

		private bool foundRtType;

	}
}
