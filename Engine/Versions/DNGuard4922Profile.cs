namespace DNGuard_Unpacker.Versions
{
    internal sealed class DNGuard4922Profile : ModernVersionProfile
    {
        internal override uint Marker => 0x001F007CU;
        internal override int KeyIndex => 14;
        internal override uint Settings(uint[] w) => w[3] ^ w[28] ^ w[22];
        internal override int MethodsCountIndex => 12;
        internal override int TableIndex => 23;
        internal override int CompressedMethodsIndex => 24;
        internal override int LehSizeIndex => 19;
        internal override int TokenSizeIndex => 20;
        internal override int TokenOffsetIndex => 8;
        internal override uint LocalsOffset(uint[] w) => w[16];
        internal override uint ResourceCount(uint[] w, bool second) => w[10] >> 16;
        internal override int ResourceOffsetIndex => 18;
        internal override int StringsOffsetIndex => 11;
        internal override uint EncryptedStringsSize(uint[] w, bool second) => w[25];
        internal override int EhSizeOffset(bool lengthFirst) => 8;
        internal override int LocalCountOffset => 10;
        internal override int DescriptorSizeOffset => 6;
        internal override ModernCipherSelection SelectCipher(int originalId, bool lengthFirst)
        {
            int id = originalId;
            switch (id) { case 1: id=2; break; case 2: id=1; break; case 6: id=9; break;
                case 9: id=10; break; case 10: id=6; break; case 12: id=15; break; case 15: id=4; break; }
            return new ModernCipherSelection { Id = id, LegacyBlowfish = id == 7, SpecialRotatingXXTea = id == 5,
                BlowfishMode = id == 12 || id == 13 ? 2 : id == 14 ? 1 : -1 };
        }
    }
}
