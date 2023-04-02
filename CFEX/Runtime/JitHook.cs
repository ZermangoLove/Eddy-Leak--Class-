using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Protector.Runtime
{
 internal static class JitHook
 {


  [DllImport("kernel32.dll", EntryPoint = "GetProcAddress")]
  private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

  [DllImport("kernel32.dll", EntryPoint = "LoadLibrary")]
  private static extern IntPtr LoadLibrary(string dllToLoad);

  [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
  private delegate void Invoke_();
  public static void InvokeInternal()
  {
   Assembly this_asm = MethodBase.GetCurrentMethod().Module.Assembly;

   Stream lib_stream = this_asm.GetManifestResourceStream(Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI0))));

   if(lib_stream != null)
   {
    byte[] lib_data = new byte[lib_stream.Length];
    lib_stream.Read(lib_data, 0, lib_data.Length);

    if(lib_data != null)
    {
     string lib_path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()+".dll");
     File.WriteAllBytes(lib_path, lib_data);
     if(File.Exists(lib_path))
     {
      IntPtr dll = LoadLibrary(lib_path);
      IntPtr addr = GetProcAddress(dll, "Invoke");
      Invoke_ i = (Invoke_)Marshal.GetDelegateForFunctionPointer(addr, typeof(Invoke_));
      i();
     }
    }
   }
  }

 }
}
