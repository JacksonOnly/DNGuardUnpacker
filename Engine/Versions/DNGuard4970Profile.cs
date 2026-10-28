namespace DNGuard_Unpacker.Versions
{

    internal sealed class DNGuard4970Profile : ModernVersionProfile
    {
        internal override uint Marker => 0x0020007CU;
        internal override int KeyIndex => 14;
        
        internal override bool ProbeTokenOffsetShift => true;
        internal override uint Settings(uint[] w) => w[5] ^ w[13] ^ w[30];
        internal override int MethodsCountIndex => 11;
        internal override int ExpandedMethodsIndex => 23;

        internal override int TableIndex => -1;
        internal override uint FirstMethodsRva(uint[] w, uint settings) => 0;
        internal override int CompressedMethodsIndex => 24;
        internal override int LehSizeIndex => 28;
        internal override int TokenSizeIndex => 26;
        internal override int TokenOffsetIndex => 10;
        internal override uint LocalsOffset(uint[] w) => w[27];
        
        internal override uint ResourceCount(uint[] w, bool second) => w[29] & 0xFFFFU;
        internal override int ResourceOffsetIndex => 25;
        internal override int StringsOffsetIndex => 17;
        internal override uint EncryptedStringsSize(uint[] w, bool second) => w[16];
        internal override int EhSizeOffset(bool lengthFirst) => 8;
        internal override int LocalCountOffset => 6;
        internal override int DescriptorSizeOffset => 10;
        internal override ModernCipherSelection SelectCipher(int originalId, bool lengthFirst)
        {
            int id = originalId;
            switch (id)
            {
                case 2: break;
                case 3: id = 1; break;
                case 6: id = 4; break;
                case 7: id = 9; break;
                case 8: id = 3; break;
                case 9: id = 10; break;
                case 10: id = 9; break;
                case 11: id = 6; break;
                case 12: case 13: case 14: case 15: break;
                default: throw new System.NotSupportedException("Unverified 4.97 cipher ID " + originalId);
            }
            return new ModernCipherSelection
            {
                Id = id,
                ForceRotatingXXTea = originalId == 7,
                BlowfishMode = originalId == 12 ? 2 : originalId == 13 ? 0 : originalId == 14 ? 1 : -1
            };
        }
    }
}
