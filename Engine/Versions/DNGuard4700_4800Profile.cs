namespace DNGuard_Unpacker.Versions
{
    
    internal sealed class DNGuard4700_4800Profile : ModernVersionProfile
    {
        internal override uint Marker => 0x001E007CU;
        internal override bool Chained => false;
        internal override int KeyIndex => 17;
        internal override uint Settings(uint[] w) => w[1] ^ w[2] ^ w[3];
        internal override int MethodsCountIndex => 21;
        internal override int ExpandedMethodsIndex => 23;
        internal override int TableIndex => 16;
        internal override uint SecondMethodsRva(uint[] w, uint settings) => w[24] ^ w[17] ^ settings;
        internal override int CompressedMethodsIndex => 24;
        internal override uint CompressedMethodsSize(uint[] w, bool second) => w[second ? 25 : 24];
        internal override int LehSizeIndex => 20;
        internal override int TokenSizeIndex => 22;
        internal override int TokenOffsetIndex => 14;
        internal override uint LocalsOffset(uint[] w) => checked(w[14] - ((w[18] + 3U) & ~3U));
        internal override uint ResourceCount(uint[] w, bool second) => second ? w[5] & 0xFFFFU : w[7] >> 16;
        internal override int ResourceOffsetIndex => 19;
        internal override int StringsOffsetIndex => 9;
        internal override uint EncryptedStringsSize(uint[] w, bool second) => w[second ? 28 : 27];
        internal override int EhSizeOffset(bool lengthFirst) => lengthFirst ? 6 : 0;
        internal override int LocalCountOffset => 4;
        internal override int DescriptorSizeOffset => -1;
        internal override ModernCipherSelection SelectCipher(int originalId, bool lengthFirst)
        {
            int id = lengthFirst && originalId == 11 ? 9 : originalId;
            int mode = id == 12 ? 2 : id == 13 ? 0 : id == 14 ? 1 : -1;
            if (mode >= 0 && lengthFirst && id != 13) mode = mode == 2 ? 1 : 2;
            return new ModernCipherSelection { Id = id, BlowfishMode = mode,
                ForceRotatingXXTea = lengthFirst && originalId == 11 };
        }
    }
}
