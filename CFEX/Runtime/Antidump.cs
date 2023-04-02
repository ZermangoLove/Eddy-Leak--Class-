using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Runtime
{
 internal static class AntiDump
 {
  [DllImport("kernel32.dll", EntryPoint = "VirtualProtect")]
  internal unsafe static extern bool VirtualProtect(byte* a, int b, uint c, ref uint d);
  public  static unsafe void Init()
  {
   byte* ptr = (byte*)((void*)Marshal.GetHINSTANCE(typeof(AntiDump).Module));
   byte* ptr6 = ptr + 60;
   ptr6 = ptr + *(uint*)ptr6;
   ptr6 += 6;
   ushort num15 = *(ushort*)ptr6;
   ptr6 += 14;
   ushort num16 = *(ushort*)ptr6;
   ptr6 = ptr6 + 4 + num16;
   UIntPtr uintPtr = (UIntPtr)11;
   uint num17 = 0;
   bool flag3 = VirtualProtect(ptr6 - 16, 8, 64u, ref num17);
   *(int*)(ptr6 - 12) = 0;
   byte* ptr7 = ptr + *(uint*)(ptr6 - 16);
   *(int*)(ptr6 - 16) = 0;
   bool flag4 = VirtualProtect(ptr7, 72, 64u, ref num17);
   byte* ptr8 = ptr + *(uint*)(ptr7 + 8);
   *(int*)ptr7 = 0;
   *(int*)(ptr7 + 4) = 0;
   *(int*)(ptr7 + (int)2 * 4) = 0;
   *(int*)(ptr7 + (int)3 * 4) = 0;
   bool flag5 = VirtualProtect(ptr8, 4, 64u, ref num17);
   *(int*)ptr8 = 0;
   for (int j = 0; j < (int)num15; j++)
   {
    bool flag6 = VirtualProtect(ptr6, 8, 64u, ref num17);
    Marshal.Copy(new byte[8], 0, (IntPtr)((void*)ptr6), 8);
    ptr6 += 40;
   }
  }
 }
}
