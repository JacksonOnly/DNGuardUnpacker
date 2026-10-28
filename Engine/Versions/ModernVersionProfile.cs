using System;
using System.Linq;
namespace DNGuard_Unpacker.Versions
{

    internal abstract class ModernVersionProfile
    {
        internal abstract uint Marker { get; }
        internal virtual int HeaderSize => 124;
        internal virtual bool ValidateDecodedMethods => false;
        internal virtual bool ProbeLegacyCiphers => false;
        internal virtual bool Chained => true;
        internal virtual bool HasAlternateBlockLayout => true;

        internal virtual uint KindMask => 0xFU;
        internal virtual int TableFeedbackWidth => 1;
        internal virtual byte TableFeedbackInitial => 0;
        internal virtual bool ProbeTableFeedback => false;
        internal virtual bool ProbeTokenOffsetShift => ProbeTableFeedback;
        internal virtual int RecoveredTableTokenOffsetShift => TokenOffsetShift;
        internal virtual int TokenOffsetShift => 1;
        internal virtual bool ProbeTokenSalt => false;
        internal virtual bool CompatibilityTokenMask => false;
        internal virtual bool RefineEquivalentCiphers => false;
        internal virtual bool HasTerminalTokenTable => false;
        internal abstract int KeyIndex { get; }
        internal virtual int EncryptionIndex => 2;
        internal abstract uint Settings(uint[] w);
        internal abstract int MethodsCountIndex { get; }
        internal virtual int ExpandedMethodsIndex => 21;
        internal abstract int TableIndex { get; }
        internal virtual uint FirstMethodsRva(uint[] w, uint settings) => w[TableIndex] ^ w[KeyIndex] ^ settings;
        internal virtual uint SecondMethodsRva(uint[] w, uint settings) => FirstMethodsRva(w, settings);
        internal abstract int CompressedMethodsIndex { get; }
        internal abstract int LehSizeIndex { get; }
        internal abstract int TokenSizeIndex { get; }
        internal abstract int TokenOffsetIndex { get; }
        internal abstract uint LocalsOffset(uint[] w);
        internal abstract uint ResourceCount(uint[] w, bool second);
        internal abstract int ResourceOffsetIndex { get; }
        internal abstract int StringsOffsetIndex { get; }
        internal abstract uint EncryptedStringsSize(uint[] w, bool second);
        internal virtual uint CompressedMethodsSize(uint[] w, bool second) => w[CompressedMethodsIndex];
        internal abstract int EhSizeOffset(bool lengthFirst);
        internal virtual int MethodLengthOffset(bool lengthFirst) => lengthFirst ? 0 : 8;
        internal abstract int LocalCountOffset { get; }
        internal abstract int DescriptorSizeOffset { get; }
        internal abstract ModernCipherSelection SelectCipher(int originalId, bool lengthFirst);
    }
    internal sealed class ModernCipherSelection
    {
        internal int Id;
        internal int BlowfishMode = -1;
        internal bool LegacyBlowfish;
        internal int LegacyCipherId = -1;
        internal bool SpecialRotatingXXTea;
        internal bool ForceRotatingXXTea;
    }
    internal static class ModernVersionRegistry
    {

        internal static readonly ModernVersionProfile[] Profiles = {
            new DNGuard4700_4800Profile(), new DNGuard4922Profile(), new DNGuard493Profile(), new DNGuard494Profile(), new DNGuard4960Profile(), new DNGuard4970Profile(), new DNGuard4600Profile(), new DirectHeader124FeedbackProfile(), new DirectHeader112GroupedProfile(), new DirectHeader108ReorderedProfile()
        };
        static ModernVersionRegistry()
        {
            if (Profiles.GroupBy(p => new { p.Marker, p.KeyIndex }).Any(g => g.Count() != 1))
                throw new InvalidOperationException("Duplicate modern version marker/key.");
        }
        internal static ModernVersionProfile Find(uint marker) => Array.Find(Profiles, p => p.Marker == marker);
    }
}
