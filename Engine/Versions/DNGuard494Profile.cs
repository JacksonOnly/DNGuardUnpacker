namespace DNGuard_Unpacker.Versions
{

    internal sealed class DNGuard494Profile : ModernVersionProfile
    {
        internal override uint Marker => 0x001F007C;
        internal override int KeyIndex => 17;
        internal override bool ValidateDecodedMethods => true;
        internal override uint Settings(uint[] w) => w[8] ^ w[28] ^ w[14];
        internal override int MethodsCountIndex => 10;
        internal override int ExpandedMethodsIndex => 22;

        internal override int TableIndex => 24;
        internal override int CompressedMethodsIndex => 26;
        internal override int LehSizeIndex => 25;
        internal override int TokenSizeIndex => 29;
        internal override int TokenOffsetIndex => 12;
        internal override uint LocalsOffset(uint[] w) => w[13];
        internal override uint ResourceCount(uint[] w, bool second) => w[11] >> 16;
        internal override int ResourceOffsetIndex => 27;
        internal override int StringsOffsetIndex => 9;
        internal override uint EncryptedStringsSize(uint[] w, bool second) => w[18];
        internal override int EhSizeOffset(bool lengthFirst) => 10;
        internal override int LocalCountOffset => 8;
        internal override int DescriptorSizeOffset => 4;

        internal override uint KindMask => 7U;
        internal override ModernCipherSelection SelectCipher(int originalId, bool lengthFirst)
        {
            int id = originalId;
            switch (id)
            {
                case 1: id = 2; break;
                case 2: id = 1; break;
                case 5: id = 6; break;
                case 6: id = 4; break;
                case 9: id = 9; break;
                case 10: id = 10; break;
                case 11: id = 5; break;
                case 15: id = 15; break;
            }
            return new ModernCipherSelection
            {
                Id = id,
                SpecialRotatingXXTea = originalId == 11
            };
        }
    }
}
