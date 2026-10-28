using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace DNGuard_Unpacker
{
    
    public sealed class LayoutProbeReport
    {
        public int SchemaVersion { get; set; } = 1;
        public bool Recognized { get; set; }
        public string ValidationScope { get; set; } = "header-and-blocks";
        public string Layout { get; set; }
        public int HeaderSize { get; set; }
        public uint Marker { get; set; }
        public string Diagnostic { get; set; }
        public List<LayoutKeyEvidence> Keys { get; set; } = new List<LayoutKeyEvidence>();
        public List<LayoutBlockEvidence> Blocks { get; set; } = new List<LayoutBlockEvidence>();
        public LayoutDeepEvidence DeepValidation { get; set; }
        public LayoutExternalBlockEvidence ExternalMethods { get; set; }

        
        public void Write(string path)
        {
            path = Path.GetFullPath(path);
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
                new DataContractJsonSerializer(typeof(LayoutProbeReport)).WriteObject(stream, this);
        }
    }
    
    [Serializable, DataContract]
    public sealed class LayoutExternalBlockEvidence
    {
        
        [DataMember]
        public bool HeaderAndKeyValidated { get; set; }
        
        [DataMember]
        public bool Available { get; set; }
        
        [DataMember]
        public string SearchScope { get; set; }
        
        [DataMember]
        public uint MethodsCount { get; set; }
        
        [DataMember]
        public ulong TableBytes { get; set; }
        
        [DataMember]
        public uint CompressedMethodsBytes { get; set; }
        
        [DataMember]
        public uint CompressedLehBytes { get; set; }
        
        [DataMember]
        public ulong ExpectedTotalBytes { get; set; }
        
        [DataMember]
        public uint ExpandedMethodsBytes { get; set; }
        
        [DataMember]
        public int ExpandedLengthMarkerOccurrences { get; set; }
    }
    public sealed class LayoutKeyEvidence
    {
        public int EncryptionIndex { get; set; }
        public int KeyIndex { get; set; }
        public uint KeyRva { get; set; }
        public uint EncryptionDword { get; set; }
        public bool Chained { get; set; }
    }
    public sealed class LayoutBlockEvidence
    {
        public uint MethodsRva { get; set; }
        public uint MethodsCount { get; set; }
        public int CountIndex { get; set; } = -1;
        public uint ExpandedSize { get; set; }
        public int ExpandedIndex { get; set; } = -1;
        public int TableXorLength { get; set; }
        public uint DescriptorCount { get; set; }
    }
    public sealed class LayoutDeepEvidence
    {
        public bool Succeeded { get; set; }
        public string Diagnostic { get; set; }
        public int MethodsValidated { get; set; }
        public int AnonymousStringsValidated { get; set; }
        public uint StringsRva { get; set; }
        public uint StringsSize { get; set; }
        public int TableFeedbackWidth { get; set; }
        public int TableFeedbackInitial { get; set; }
        public int TableXorLength { get; set; }
        public bool PackedLegacyRecords { get; set; }
        public int TokenOffsetShift { get; set; }
        public uint TokenSalt { get; set; }
        public uint CompressedMethodsSize { get; set; }
        public uint CompressedLehSize { get; set; }
        public uint LocalsOffset { get; set; }
        public uint TokenTableOffset { get; set; }
        public uint TokenTableSize { get; set; }
        public int MethodLengthOffset { get; set; } = -1;
        public int ExceptionSizeOffset { get; set; } = -1;
        public int LocalCountOffset { get; set; } = -1;
        public int LocalDescriptorSizeOffset { get; set; } = -1;
        public List<LayoutFieldEvidence> HeaderFields { get; set; } = new List<LayoutFieldEvidence>();
        public List<LayoutCipherEvidence> Ciphers { get; set; } = new List<LayoutCipherEvidence>();
    }
    public sealed class LayoutFieldEvidence
    {
        public string Name { get; set; }
        public int WordIndex { get; set; }
    }
    public sealed class LayoutCipherEvidence
    {
        public int AlgorithmId { get; set; }
        public bool Inferred { get; set; }
        public int CipherId { get; set; }
        public int LegacyCipherId { get; set; }
        public bool LegacyUsesPrimary { get; set; }
        public int BlowfishMode { get; set; }
        public bool LegacyBlowfish { get; set; }
        public bool SpecialRotatingXXTea { get; set; }
        public bool ForceRotatingXXTea { get; set; }
        public bool LengthFirst { get; set; }
        public int PrefixTransform { get; set; }
    }
}
