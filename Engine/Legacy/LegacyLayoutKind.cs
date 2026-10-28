namespace DNGuard_Unpacker
{
    
    internal enum LegacyLayoutKind
    {
        Unknown, Header104Standard, Header104Reordered, Header104Wide, Header104Shifted, Header104Permuted,
        Header108, Header112Standard, Header112Alternate, Header124Direct,
        Header124Alternate, Header124Unencrypted, Header128, Header128Inline, Header152,
        Header152Inline, Header152Tokens, Header156Inline,
        Header160Separated, Header160Permuted, Header160Tokens
    }
}
