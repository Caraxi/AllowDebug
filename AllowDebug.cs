using Dalamud.Plugin;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AllowDebug {
    public class AllowDebug : IDalamudPlugin {

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        public string Name => "AllowDebug";
        public DalamudPluginInterface PluginInterface { get; private set; }

        private IntPtr scanAddress;
        private readonly byte[] nop = new byte[] { 0x31, 0xC0, 0x90, 0x90, 0x90, 0x90 };
        private byte[] original;

        public void Initialize(DalamudPluginInterface pluginInterface) {
            this.PluginInterface = pluginInterface;
            original = new byte[nop.Length];
            scanAddress = PluginInterface.TargetModuleScanner.ScanText("FF 15 ?? ?? ?? ?? 85 C0 74 11");
            if (scanAddress != IntPtr.Zero) {
                PluginLog.Log($"Overwriting Debug Check @ 0x{scanAddress.ToInt64():X}");
                ReadProcessMemory(Process.GetCurrentProcess().Handle, scanAddress, original, nop.Length, out _);
                WriteProcessMemory(Process.GetCurrentProcess().Handle, scanAddress, nop, nop.Length, out _);
            }
        }

        public void Dispose() {
            if (scanAddress != IntPtr.Zero && original != null) WriteProcessMemory(Process.GetCurrentProcess().Handle, scanAddress, original, original.Length, out _);
        }

    }
}
