using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Security.Cryptography;

namespace Eddy_Protector_Runtime
{
 class KeysHiderRuntime
 {
  public static int GetKey(string name)
  {
   byte[] result = new byte[0];
   Assembly assembly = MethodBase.GetCurrentMethod().Module.Assembly;
   var manifestResourceStream = assembly.GetManifestResourceStream(name);

   if (manifestResourceStream != null)
   {
    byte[] array = new byte[manifestResourceStream.Length];
    manifestResourceStream.Read(array, 0, array.Length);
    result = array;
   }

   string base64_str = Encoding.UTF8.GetString(result);
   byte[] from_base64 = Convert.FromBase64String(base64_str);

   byte[] key = SHA1.Create().ComputeHash(BitConverter.GetBytes(1993));
   for (int i = (from_base64.Length * 2) + key.Length; i >= 0; i += -1)
   {
    from_base64[i % from_base64.Length] = (byte)(((int)(from_base64[i % from_base64.Length] ^ key[i % key.Length]) - (int)(from_base64[(i + 1) % from_base64.Length]) + 256) % 256);
   }

   int num = BitConverter.ToInt32(from_base64,0);

   return num;
  }
 }
}
