namespace DNGuard_Unpacker.Versions
{
    
    internal sealed class DirectHeader124FeedbackProfile : ModernVersionProfile
    {
        internal override uint Marker => 0x001F007C;
        internal override bool Chained => false;
        internal override bool HasAlternateBlockLayout => false;
        internal override int TableFeedbackWidth => 2;
        internal override byte TableFeedbackInitial => 255;
        internal override bool ProbeTableFeedback => true;
        internal override int TokenOffsetShift => 0;
        internal override bool ProbeTokenSalt => true;
        internal override int KeyIndex => 10;
        internal override uint Settings(uint[] w) => w[1] ^ w[2] ^ w[3];
        internal override int MethodsCountIndex => 19;
        internal override int ExpandedMethodsIndex => 21;
        internal override int TableIndex => 23;
        internal override uint FirstMethodsRva(uint[] w, uint settings) => w[23] ^ w[8] ^ w[1];
        internal override int CompressedMethodsIndex => 24;
        internal override int LehSizeIndex => 18;
        internal override int TokenSizeIndex => 20;
        internal override int TokenOffsetIndex => 28;
        internal override uint LocalsOffset(uint[] w) => w[4];
        internal override uint ResourceCount(uint[] w, bool second) => w[5] & 0xFFFF;
        internal override int ResourceOffsetIndex => 17;
        internal override int StringsOffsetIndex => 7;
        internal override uint EncryptedStringsSize(uint[] w, bool second) => w[27];
        internal override int EhSizeOffset(bool lengthFirst) => 10;
        internal override int MethodLengthOffset(bool lengthFirst) => 0;
        internal override int LocalCountOffset => 8;
        internal override int DescriptorSizeOffset => 6;
        internal override ModernCipherSelection SelectCipher(int originalId, bool lengthFirst)
            => new DNGuard4700_4800Profile().SelectCipher(originalId, true);
    }
}
