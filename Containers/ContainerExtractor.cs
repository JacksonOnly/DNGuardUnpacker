using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using dnlib.DotNet;
using dnlib.PE;

namespace DNGuard_Unpacker
{
    
    public static class ContainerExtractor
    {
        private const int MaxImageSize = 64 * 1024 * 1024;

        public static bool IsManaged(byte[] bytes)
        {
            using (var pe = new PEImage(bytes))
                return pe.ImageNTHeaders.OptionalHeader.DataDirectories[14].VirtualAddress != 0;
        }

        public static bool IsNativeDll(byte[] bytes)
        {
            using (var pe = new PEImage(bytes))
                return ((ushort)pe.ImageNTHeaders.FileHeader.Characteristics & 0x2000) != 0 &&
                    pe.ImageNTHeaders.OptionalHeader.DataDirectories[14].VirtualAddress == 0;
        }

        public static byte[] Extract(string path, int timeoutMilliseconds = 30000)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT || IntPtr.Size != 4)
                throw new PlatformNotSupportedException("Native capture currently requires Windows x86.");
            var startup = new StartupInfo { Size = Marshal.SizeOf(typeof(StartupInfo)), Flags = 1, ShowWindow = 0 };
            ProcessInfo process;
            if (!CreateProcess(path, new StringBuilder("\"" + path + "\""), IntPtr.Zero, IntPtr.Zero, false,
                2 | 0x08000000, IntPtr.Zero, Path.GetDirectoryName(path), ref startup, out process))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var clock = Stopwatch.StartNew();
            var debugEvent = new DebugEvent();
            bool pending = false;
            try
            {
                while (clock.ElapsedMilliseconds < timeoutMilliseconds)
                {
                    if (!WaitForDebugEvent(ref debugEvent, 20))
                    {
                        DebugBreakProcess(process.Process);
                        continue;
                    }
                    pending = true;
                    if (debugEvent.Code == 5) throw new InvalidDataException("Container exited before a complete managed entry module was captured.");
                    byte[] module = TryCapture(process.Process);
                    if (module != null) return module;
                    CloseEventHandles(debugEvent);
                    uint status = debugEvent.Code == 1 && debugEvent.ExceptionCode != 0x80000003 ? 0x80010001U : 0x10002U;
                    if (!ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, status))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    pending = false;
                }
                throw new TimeoutException("No complete protected managed entry module captured within " + timeoutMilliseconds + " ms.");
            }
            finally
            {
                TerminateProcess(process.Process, 0);
                if (pending)
                {
                    CloseEventHandles(debugEvent);
                    ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, 0x10002);
                }
                
                var cleanup = Stopwatch.StartNew();
                while (cleanup.ElapsedMilliseconds < 3000 && WaitForDebugEvent(ref debugEvent, 500))
                {
                    CloseEventHandles(debugEvent);
                    ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, 0x10002);
                    if (debugEvent.Code == 5) break;
                }
                CloseHandle(process.Thread);
                CloseHandle(process.Process);
            }
        }

        public static byte[] CaptureProcess(int processId)
        {
            IntPtr handle = OpenProcess(0x410, false, processId);
            if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try { return TryCapture(handle); }
            finally { CloseHandle(handle); }
        }

        private static byte[] TryCapture(IntPtr process)
        {
            ulong address = 0;
            MemoryInfo info;
            var regions = new List<MemoryInfo>();
            while (address < 0x80000000 && VirtualQueryEx(process, Pointer(address), out info, (uint)Marshal.SizeOf(typeof(MemoryInfo))) != 0)
            {
                ulong next = (uint)info.BaseAddress.ToInt32() + (ulong)info.RegionSize.ToInt32();
                if (next <= address) break;
                if (info.State == 0x1000 && (info.Protect & 0x101) == 0 && info.Type != 0x1000000)
                    regions.Add(info);
                address = next;
            }
            foreach (var region in regions)
            {
                ulong start = (uint)region.BaseAddress.ToInt32();
                int size = region.RegionSize.ToInt32();
                
                for (int offset = 0; offset < size; offset += 65536 - 1)
                {
                    byte[] chunk = Read(process, start + (uint)offset, Math.Min(65536, size - offset));
                    if (chunk == null) continue;
                    for (int i = 0; i + 1 < chunk.Length; i++)
                    {
                        if (chunk[i] != 0x4D || chunk[i + 1] != 0x5A) continue;
                        byte[] candidate = TryImage(process, start + (uint)offset + (uint)i);
                        if (candidate != null) return candidate;
                    }
                }
            }
            return null;
        }

        private static byte[] TryImage(IntPtr process, ulong address)
        {
            byte[] header = Read(process, address, 4096);
            if (header == null) return null;
            int nt = BitConverter.ToInt32(header, 60);
            if (nt < 64 || nt > 2048 || BitConverter.ToUInt32(header, nt) != 0x4550) return null;
            int optional = nt + 24;
            int magic = BitConverter.ToUInt16(header, optional);
            if (magic != 0x10B) return null;
            if (BitConverter.ToUInt32(header, optional + 208) == 0) return null;
            int imageSize = BitConverter.ToInt32(header, optional + 56);
            int headerSize = BitConverter.ToInt32(header, optional + 60);
            int count = BitConverter.ToUInt16(header, nt + 6);
            int sections = optional + BitConverter.ToUInt16(header, nt + 20);
            if (count == 0 || count > 32 || sections + count * 40 > header.Length || imageSize < 4096 || imageSize > MaxImageSize || headerSize < sections + count * 40 || headerSize > imageSize) return null;
            int fileSize = headerSize;
            for (int i = 0; i < count; i++)
            {
                int entry = sections + i * 40;
                ulong end = (ulong)BitConverter.ToUInt32(header, entry + 20) + BitConverter.ToUInt32(header, entry + 16);
                if (end > MaxImageSize) return null;
                fileSize = Math.Max(fileSize, (int)end);
            }
            byte[] flat = Read(process, address, fileSize);
            if (IsProtectedEntry(flat)) return flat;
            var file = new byte[fileSize];
            byte[] fullHeader = Read(process, address, headerSize);
            if (fullHeader == null) return null;
            Buffer.BlockCopy(fullHeader, 0, file, 0, headerSize);
            for (int i = 0; i < count; i++)
            {
                int entry = sections + i * 40;
                uint rva = BitConverter.ToUInt32(header, entry + 12);
                int length = checked((int)BitConverter.ToUInt32(header, entry + 16));
                int raw = checked((int)BitConverter.ToUInt32(header, entry + 20));
                if ((ulong)rva + (uint)length > (uint)imageSize) return null;
                if (length == 0) continue;
                byte[] section = Read(process, address + rva, length);
                if (section == null) return null;
                Buffer.BlockCopy(section, 0, file, raw, length);
            }
            return IsProtectedEntry(file) ? file : null;
        }

        private static bool IsProtectedEntry(byte[] bytes)
        {
            if (bytes == null) return false;
            try
            {
                using (var module = ModuleDefMD.Load(bytes))
                {
                    if (module.EntryPoint == null || !module.GetTypes().Any(t => t.FullName.Contains("ZYXDNGuarder"))) return false;
                    byte[] structure = null;
                    return new DNGDecrypter(module).GetStructSize(124, ref structure) == 124;
                }
            }
            catch (BadImageFormatException) { return false; }
            catch (IOException) { return false; }
            catch (ArgumentException) { return false; }
        }

        private static byte[] Read(IntPtr process, ulong address, int length)
        {
            var bytes = new byte[length];
            IntPtr read;
            return ReadProcessMemory(process, Pointer(address), bytes, length, out read) && read.ToInt64() == length ? bytes : null;
        }

        private static IntPtr Pointer(ulong address) { return new IntPtr(unchecked((int)address)); }

        private static void CloseEventHandles(DebugEvent e)
        {
            if (e.Code == 2) CloseHandle(e.Handle0);
            if (e.Code == 3) { CloseHandle(e.Handle0); CloseHandle(e.Handle1); CloseHandle(e.Handle2); }
            if (e.Code == 6) CloseHandle(e.Handle0);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MemoryInfo { public IntPtr BaseAddress, AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State, Protect, Type; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public int Size; public string Reserved, Desktop, Title; public uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
            public short ShowWindow, ReservedSize; public IntPtr ReservedPointer, StdInput, StdOutput, StdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
        [StructLayout(LayoutKind.Explicit, Size = 96)]
        private struct DebugEvent
        {
            [FieldOffset(0)] public uint Code;
            [FieldOffset(4)] public uint ProcessId;
            [FieldOffset(8)] public uint ThreadId;
            [FieldOffset(12)] public uint ExceptionCode;
            [FieldOffset(12)] public IntPtr Handle0;
            [FieldOffset(16)] public IntPtr Handle1;
            [FieldOffset(20)] public IntPtr Handle2;
        }
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInfo process);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool WaitForDebugEvent(ref DebugEvent e, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ContinueDebugEvent(uint processId, uint threadId, uint status);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DebugBreakProcess(IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] bytes, int length, out IntPtr read);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern int VirtualQueryEx(IntPtr process, IntPtr address, out MemoryInfo info, uint length);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    }
}
