namespace DNGuard_Unpacker.Versions
{
    
    internal sealed class DNGuard4600Profile : ModernVersionProfile
    {
        internal override uint Marker => 0x001D007CU;
        internal override bool Chained => false;
        internal override bool HasAlternateBlockLayout => false;
        internal override int KeyIndex => 10;
        internal override uint Settings(uint[] w) => w[1] ^ w[2] ^ w[3];
        internal override int MethodsCountIndex => 14;
        internal override int ExpandedMethodsIndex => 19;
        internal override int TableIndex => 7;
        internal override uint FirstMethodsRva(uint[] w, uint settings) => w[7] ^ w[1] ^ w[10] ^ settings;
        internal override int CompressedMethodsIndex => 21;
        internal override int LehSizeIndex => 13;
        internal override int TokenSizeIndex => 18;
        internal override int TokenOffsetIndex => 20;
        internal override uint LocalsOffset(uint[] w) => w[8];
        internal override uint ResourceCount(uint[] w, bool second) => w[6];
        internal override int ResourceOffsetIndex => 16;
        internal override int StringsOffsetIndex => 17;
        internal override uint EncryptedStringsSize(uint[] w, bool second) => w[24];
        internal override int EhSizeOffset(bool lengthFirst) => 0;
        internal override int MethodLengthOffset(bool lengthFirst) => 4;
        internal override int LocalCountOffset => 2;
        internal override int DescriptorSizeOffset => -1;
        internal override ModernCipherSelection SelectCipher(int originalId, bool lengthFirst)
        {
            
            int id;
            switch (originalId)
            {
                case 1: id = 2; break;
                case 2: return new ModernCipherSelection { LegacyCipherId = 2 };
                case 6: id = 4; break;
                case 7: id = 6; break;
                case 8: id = 7; break;
                case 9: id = 10; break;
                case 10: id = 11; break;
                case 11: id = 12; break;
                case 12: id = 9; break;
                case 13: id = 15; break;
                case 14: id = 13; break;
                case 15: id = 14; break;
                default: throw new System.NotSupportedException("Unverified 4.60 cipher ID " + originalId);
            }
            return new ModernCipherSelection { Id = id,
                BlowfishMode = id == 12 ? 2 : id == 13 ? 0 : id == 14 ? 1 : -1 };
        }
    }
}
