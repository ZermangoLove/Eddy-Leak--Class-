using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace Runtime
{
 internal unsafe class StringHider
 {
  private static long Lenght;
  private static IntPtr dataPtr;


  public static void CopyRight()
  {
   MessageBox.Show("Protected by: Eddy^CZ 2019", "Protected assembly!", MessageBoxButtons.OK, MessageBoxIcon.Information);
  }

  [DllImport("kernel32.dll")]
  public static extern void CopyMemory(void* dest, void* src, uint count);

  public static unsafe void Intitialize()
  {
   Assembly this_asm = MethodBase.GetCurrentMethod().Module.Assembly;
   string id = null;
   byte[] hash = SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI0));
   foreach (var h in hash)
   {
    id += h.ToString("x2").ToUpper();
   }
   Stream datStream = this_asm.GetManifestResourceStream(id);
   byte[] data = new byte[datStream.Length];
   datStream.Read(data, 0, data.Length);

   /* From byte[] to void* /*/
   var datPtr = (void*)Marshal.AllocHGlobal(data.Length);
   Marshal.Copy(data, 0, (IntPtr)datPtr, data.Length);
   /* Copy void* to void* */
   var targetPtr = (void*)Marshal.AllocHGlobal(data.Length);
   CopyMemory(targetPtr, datPtr, (uint)data.Length);
   /* From void* to byte[] */
   byte[] result = new byte[data.Length];
   Marshal.Copy((IntPtr)targetPtr, result, 0, data.Length);
   dataPtr = (IntPtr)targetPtr;
   Lenght = (long)data.Length;
  }

  public static unsafe string Get(uint id)
  {
   byte[] data = new byte[Lenght];
   for (long t = 0; t < Lenght; t++)
   {
    byte* bPtr = (byte*)((void*)dataPtr) + t; //Read byte*
    byte b = (byte)*bPtr; //byte* to char
    data[t] = b;
   }
   byte[] binary = data;
   List<int> entries = new List<int>();
   int hdrLenght = 0;
   List<int> dataLenght = new List<int>();

   int magic = sizeof(int);
   int sz = BitConverter.ToInt32(binary.Take(magic).ToArray(), 0);
   int[] lh = new int[sz];
   int pos = magic;
   for (int f = 0; f < sz; f++)
   {
    byte[] buff = new byte[magic];
    for (int j = 0; j < magic; j++)
    {
     buff[j] = binary[pos];
     pos++;
    }
    lh[f] = BitConverter.ToInt32(buff, 0);
    entries.Add(f);
   }
   hdrLenght = pos;
   dataLenght = lh.ToList();

   int bytesReaded = 0;
   int p = -1;
   foreach (var part in entries)
   {
    int l = dataLenght.ElementAt(part);
    byte[] buffer = new byte[l];
    int srcPos = hdrLenght + bytesReaded;
    try
    {
     Array.Copy(binary, srcPos, buffer, 0, l);
     bytesReaded += l;
     p++;
    }
    catch
    {
     throw new NotImplementedException();
    }
    if (p == id)
    {
     List<ulong> d = new List<ulong>(); //P1
     byte[] h = SHA1.Create().ComputeHash(BitConverter.GetBytes(buffer.Length));
     ulong[] i = new ulong[h.Length];
     for (int x = 0; x < h.Length; x++)
     {
      i[x] = (ulong)(h[x] << 8 | h[x] << 16 | h[x] << 24);
     }
     ulong[] u = new ulong[buffer.Length];
     for (int y = 0; y < buffer.Length; y++)
     {
      u[y] = (ulong)(buffer[y] << 8 | buffer[y] << 16 | buffer[y] << 24);
     }
     foreach (ulong ul in u)
     {
      ulong o = 0;
      foreach (ulong iv in i)
      {
       o ^= iv;
      }
      o = o ^ ul;
      d.Add(o);
     }
     d.ToArray();
     for (int z = 0; z < buffer.Length; z++)
     {
      buffer[z] = (byte)(d[z] | (d[z] >> 8) | (d[z] >> 16) | (d[z] >> 24));
     }
     return Encoding.ASCII.GetString(buffer);
    }
   }
   return null;
  }
 }
}
