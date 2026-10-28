namespace DNGuard_Unpacker.Versions
{
    internal sealed class DNGuard4960Profile : ModernVersionProfile
    {
        internal override uint Marker => 0x0020007CU;
        internal override int KeyIndex => 15;
        internal override bool ProbeTableFeedback => true;
        internal override bool ValidateDecodedMethods => true;
        internal override int RecoveredTableTokenOffsetShift => 0;
        internal override uint Settings(uint[] w) => w[14] ^ w[28] ^ w[9];
        internal override int MethodsCountIndex => 8;
        internal override int TableIndex => 25;
        internal override int CompressedMethodsIndex => 26;
        internal override int LehSizeIndex => 23;
        internal override int TokenSizeIndex => 22;
        internal override int TokenOffsetIndex => 5;
        internal override uint LocalsOffset(uint[] w) => w[12];
        internal override uint ResourceCount(uint[] w, bool second) => w[24] & 0xFFFFU;
        internal override int ResourceOffsetIndex => 27;
        internal override int StringsOffsetIndex => 18;
        internal override uint EncryptedStringsSize(uint[] w, bool second) => w[17];
        internal override int EhSizeOffset(bool lengthFirst) => 10;
        internal override int LocalCountOffset => 8;
        internal override int DescriptorSizeOffset => 4;
        internal override ModernCipherSelection SelectCipher(int originalId, bool lengthFirst)
        {
            int id = originalId;
            switch (id) { case 8: id=9; break; case 7: id=4; break; case 9: id=6; break;
                case 6: id=3; break; case 11: id=13; break; case 1: id=2; break; case 2: id=1; break; }
            return new ModernCipherSelection { Id = id, LegacyBlowfish = id == 7,
                ForceRotatingXXTea = id == 14, BlowfishMode = id == 12 ? (lengthFirst ? 1 : 2) : id == 13 ? (originalId == 11 ? 0 : 2) : -1 };
        }
    }
}
