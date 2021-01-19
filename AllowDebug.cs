using Dalamud.Plugin;
using System;
using System.Runtime.InteropServices;

namespace AllowDebug {
    public class AllowDebug : IDalamudPlugin {
        public string Name => "AllowDebug";
        private readonly byte[] nop = { 0x31, 0xC0, 0x90, 0x90, 0x90, 0x90 };

        public void Initialize(DalamudPluginInterface pluginInterface) {
            try {
                var scanAddress = pluginInterface.TargetModuleScanner.ScanText("FF 15 ?? ?? ?? ?? 85 C0 74 11");
                if (scanAddress == IntPtr.Zero) throw new Exception();
                PluginLog.Log($"Overwriting Debug Check @ 0x{scanAddress.ToInt64():X}");
                Marshal.Copy(nop, 0, scanAddress, nop.Length);
            } catch {
                PluginLog.Log("Failed to overwrite debug check.");
            }
        }
        public void Dispose() { }
    }
}
