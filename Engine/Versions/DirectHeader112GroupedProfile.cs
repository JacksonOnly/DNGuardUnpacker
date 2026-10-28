namespace DNGuard_Unpacker.Versions
{
    internal sealed class DirectHeader112GroupedProfile : ModernVersionProfile
    {
        internal override uint Marker => 0x001C0070;
        internal override int HeaderSize => 112;
        internal override bool Chained => false;
        internal override bool HasAlternateBlockLayout => false;
        internal override bool ValidateDecodedMethods => true;
        internal override bool ProbeLegacyCiphers => true;
        internal override uint KindMask => 7;
        internal override int KeyIndex => 7;
        internal override uint Settings(uint[] w) => w[1] ^ w[2] ^ w[3];
        internal override int MethodsCountIndex => 11;
        internal override int ExpandedMethodsIndex => 17;
        internal override int TableIndex => 26;
        
        internal override uint FirstMethodsRva(uint[] w, uint settings) => 0;
        internal override int CompressedMethodsIndex => 22;
        internal override int LehSizeIndex => 9;
        internal override int TokenSizeIndex => 25;
        internal override int TokenOffsetIndex => 24;
        internal override uint LocalsOffset(uint[] w) => w[10];
        internal override uint ResourceCount(uint[] w, bool second) => w[14] & 0xFFFF;
        internal override int ResourceOffsetIndex => 13;
        internal override int StringsOffsetIndex => 19;
        internal override uint EncryptedStringsSize(uint[] w, bool second) => w[18];
        internal override int EhSizeOffset(bool lengthFirst) => 0;
        internal override int MethodLengthOffset(bool lengthFirst) => 4;
        internal override int LocalCountOffset => 2;
        internal override int DescriptorSizeOffset => 8;
        internal override ModernCipherSelection SelectCipher(int originalId, bool lengthFirst)
            => new DNGuard4700_4800Profile().SelectCipher(originalId, true);
    }
}
