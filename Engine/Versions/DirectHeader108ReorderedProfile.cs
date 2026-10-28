namespace DNGuard_Unpacker.Versions
{
    
    internal sealed class DirectHeader108ReorderedProfile : ModernVersionProfile
    {
        internal override uint Marker => 0x001B006C;
        internal override int HeaderSize => 108;
        internal override bool Chained => false;
        internal override bool HasAlternateBlockLayout => false;
        internal override bool ValidateDecodedMethods => true;
        internal override bool ProbeLegacyCiphers => true;
        internal override bool CompatibilityTokenMask => true;
        internal override bool RefineEquivalentCiphers => true;
        internal override bool HasTerminalTokenTable => true;
        internal override int EncryptionIndex => 3;
        internal override int KeyIndex => 10;
        internal override uint Settings(uint[] w) => w[1] ^ w[2] ^ w[3];
        internal override int MethodsCountIndex => 12;
        internal override int ExpandedMethodsIndex => 13;
        internal override int TableIndex => 22;
        internal override uint FirstMethodsRva(uint[] w, uint settings) => w[22] ^ w[5] ^ settings;
        internal override int CompressedMethodsIndex => 25;
        internal override int LehSizeIndex => 11;
        internal override int TokenSizeIndex => 23;
        internal override int TokenOffsetIndex => 24;
        internal override uint LocalsOffset(uint[] w) => w[6];
        internal override uint ResourceCount(uint[] w, bool second) => w[9];
        internal override int ResourceOffsetIndex => 4;
        internal override int StringsOffsetIndex => 20;
        internal override uint EncryptedStringsSize(uint[] w, bool second) => w[14];
        internal override int EhSizeOffset(bool lengthFirst) => 4;
        internal override int MethodLengthOffset(bool lengthFirst) => 8;
        internal override int LocalCountOffset => 2;
        internal override int DescriptorSizeOffset => 6;
        internal override ModernCipherSelection SelectCipher(int originalId, bool lengthFirst)
            => new DNGuard4700_4800Profile().SelectCipher(originalId, true);
    }
}
