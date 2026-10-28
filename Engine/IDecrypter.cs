using System;
using System.Collections.Generic;

namespace DNGuard_Unpacker
{
	
	public interface IDecrypter
	{
		
		void DecryptInternal(ref byte[] fileData);

		void ParseStructure();

		void RestoreMethods();

		void ReadMethods();

		bool IsHVMTechnologyEnabled();

		Dictionary<uint, uint> GetAnonymousTokens();

		string ReadUserStringFromOffset(uint offset);
	}
}
