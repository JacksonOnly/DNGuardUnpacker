namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        internal int RemoveProvenFakeTypes(dnlib.DotNet.MethodDef initialize)
        {
            return ProvenFakeTypeCleanup.Run(this.module, this.DataStructure._MethodsOffsetTable, this.DataStructure.Encryption_Dword, initialize);
        }
    }
}
