namespace DNGuard_Unpacker.Versions
{

    internal sealed class DNGuard493Profile : ModernVersionProfile
    {
        internal override uint Marker => 0x001F007C;
        internal override int KeyIndex => 25;
        internal override bool ValidateDecodedMethods => true;
        internal override uint Settings(uint[] w) => w[4] ^ w[28] ^ w[23];
        internal override int MethodsCountIndex => 11;
        internal override int ExpandedMethodsIndex => 17;

        internal override int TableIndex => 27;
        internal override int CompressedMethodsIndex => 20;
        internal override int LehSizeIndex => 19;
        internal override int TokenSizeIndex => 29;
        internal override int TokenOffsetIndex => 22;
        internal override uint LocalsOffset(uint[] w) => w[13];
        internal override uint ResourceCount(uint[] w, bool second) => w[9] >> 16;
        internal override int ResourceOffsetIndex => 21;
        internal override int StringsOffsetIndex => 10;
        internal override uint EncryptedStringsSize(uint[] w, bool second) => w[26];
        internal override int EhSizeOffset(bool lengthFirst) => 4;
        internal override int LocalCountOffset => 6;
        internal override int DescriptorSizeOffset => 8;

        internal override uint KindMask => 7U;
        internal override ModernCipherSelection SelectCipher(int originalId, bool lengthFirst)
        {
            int id = originalId;
            int mode = -1;
            switch (id)
            {
                case 2: id = 1; break;
                case 6: id = 4; break;
                case 7: id = 9; break;
                case 12: id = 10; break;
                case 15: id = 12; mode = 1; break;
            }
            return new ModernCipherSelection { Id = id, BlowfishMode = mode };
        }
    }
}
