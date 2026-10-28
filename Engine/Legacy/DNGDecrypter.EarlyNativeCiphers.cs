using System;
using System.IO;

namespace DNGuard_Unpacker
{
    public partial class DNGDecrypter
    {
        
        
        
        private static byte[] DecodeEarlyNative(byte[] bytes, byte[] key, uint salt, int id)
        {
            if (key == null || key.Length != 16) throw new ArgumentException("Early cipher requires a 16-byte key.");
            if (id == 8)
            {
                var state = new byte[256];
                var schedule = new byte[256];
                unchecked
                {
                    for (int i = 0; i < 256; i++)
                    {
                        schedule[i] = (byte)(key[i & 15] ^ (i >> 4));
                        state[i] = (byte)(i ^ (byte)(salt >> (8 * (i & 3))) ^ schedule[i]);
                    }
                    int j = 0;
                    for (int i = 0; i < 256; i++)
                    {
                        j = (j + state[i] + schedule[i]) & 255;
                        byte swap = state[i]; state[i] = state[j]; state[j] = swap;
                    }
                    int x = 0; j = 0;
                    for (int at = 0; at < bytes.Length; at++)
                    {
                        x = (x + 1) & 255; j = (j + state[x]) & 255;
                        byte swap = state[x]; state[x] = state[j]; state[j] = swap;
                        bytes[at] ^= state[(swap + state[x]) & 255];
                    }
                }
                return bytes;
            }
            if (id != 1 && id != 6) throw new NotSupportedException("Unknown native early cipher.");
            if ((bytes.Length & 7) != 0) throw new InvalidDataException("Early block cipher payload is not padded to eight bytes.");
            var words = new uint[4];
            for (int i = 0; i < 4; i++) words[i] = BitConverter.ToUInt32(key, i * 4);
            int rounds = id == 1 ? 16 : 32, shift = id == 1 ? 3 : 5;
            unchecked
            {
                uint delta = salt ^ 0x7A5993C5U;
                for (int at = 0; at < bytes.Length; at += 8)
                {
                    uint left = BitConverter.ToUInt32(bytes, at) ^ salt;
                    uint right = BitConverter.ToUInt32(bytes, at + 4) ^ salt;
                    uint sum = delta * (uint)rounds;
                    for (int round = 0; round < rounds && sum != 0; round++)
                    {
                        right -= (left ^ sum) + words[(sum >> 11) & 3] + ((left << shift) ^ (left >> 7));
                        sum -= delta;
                        left -= (right ^ sum) + words[sum & 3] + ((right << shift) ^ (right >> 7));
                    }
                    Buffer.BlockCopy(BitConverter.GetBytes(left), 0, bytes, at, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes(right), 0, bytes, at + 4, 4);
                }
            }
            return bytes;
        }
    }
}
