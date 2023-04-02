using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Protector.Runtime
{
 internal static class AntiTamperNormal
 {
  [DllImport("kernel32.dll", EntryPoint = "VirtualProtect")]
  static extern bool _(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

  static unsafe void Initialize()
  {
   Module m = typeof(AntiTamperNormal).Module;
   string n = m.FullyQualifiedName;
   bool f = n.Length > 0 && n[0] == '<';
   var b = (byte*)Marshal.GetHINSTANCE(m);
   byte* p = b + *(uint*)(b + 0x3c);
   ushort s = *(ushort*)(p + 0x6);
   ushort o = *(ushort*)(p + 0x14);

   uint* e = null;
   uint l = 0;
   var r = (uint*)(p + 0x18 + o);

   ///* Old keys */
   //uint z = (uint)Mutation.KeyI1;
   //uint x = (uint)Mutation.KeyI2;
   //uint c = (uint)Mutation.KeyI3;
   //uint v = (uint)Mutation.KeyI4;

   /* Retrieve new keys */
   byte[] payload = GetThePayload(Mutation.KeyI0);

   /* New keys */
   uint z = RestoreKey(1, payload);
   uint x = RestoreKey(2, payload);
   uint c = RestoreKey(3, payload);
   uint v = RestoreKey(4, payload);

   for (int i = 0; i < s; i++)
   {
    uint g = (*r++) * (*r++);
    if (g == RestoreKey(0, payload))
    {
     e = (uint*)(b + (f ? *(r + 3) : *(r + 1)));
     l = (f ? *(r + 2) : *(r + 0)) >> 2;
    }
    else if (g != 0)
    {
     var q = (uint*)(b + (f ? *(r + 3) : *(r + 1)));
     uint j = *(r + 2) >> 2;
     for (uint k = 0; k < j; k++)
     {
      uint t = (z ^ (*q++)) + x + c * v;
      z = x;
      x = c;
      x = v;
      v = t;
     }
    }
    r += 8;
   }

   uint[] y = new uint[0x10], d = new uint[0x10];
   for (int i = 0; i < 0x10; i++)
   {
    y[i] = v;
    d[i] = x;
    z = (x >> 5) | (x << 27);
    x = (c >> 3) | (c << 29);
    c = (v >> 7) | (v << 25);
    v = (z >> 11) | (z << 21);
   }
   Mutation.Crypt(y, d);

   uint w = 0x40;
   _((IntPtr)e, l << 2, w, out w);

   if (w == 0x40)
    return;

   uint h = 0;
   for (uint i = 0; i < l; i++)
   {
    *e ^= y[h & 0xf];
    y[h & 0xf] = (y[h & 0xf] ^ (*e++)) + 0x3dbb2819;
    h++;
   }

   #region Not used
   //MethodInfo be = null;
   //foreach(var method in m.GetMethods(BindingFlags.Static | BindingFlags.NonPublic))
   //{
   // if (method.Name == "ReplacementMethod")
   //  be = method;
   //}
   //var meth = (MethodInfo)MethodBase.GetCurrentMethod();


   //if(be == null)
   // Console.WriteLine("wTF IS HAPPENING!==!=");
   ////ok try now
   //Replace(be, meth);
   ////wait a second this if nF2 right? yes 
   #endregion Not Used
  }


  public static byte[] GetThePayload(int part)
  {
   String normalizedFileName = Path.GetFullPath(Environment.ExpandEnvironmentVariables(Process.GetCurrentProcess().MainModule.FileName));
   byte[] originalFile = File.ReadAllBytes(normalizedFileName);

   Byte[] buffer = new Byte[4];
   FileInfo information = new FileInfo(normalizedFileName);
   if (information.Exists)
   {
    using (Stream stream = information.Open(FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
    {
     byte[] Result = null;
     stream.Seek(0x3c, SeekOrigin.Begin);
     stream.Read(buffer, 0, 4);
     Int32 e_lfanew = BitConverter.ToInt32(buffer, 0);
     stream.Seek(e_lfanew + 0x6, SeekOrigin.Begin);
     stream.Read(buffer, 0, 2);
     Int16 dwNumSections = BitConverter.ToInt16(buffer, 0);
     stream.Seek(e_lfanew + 0x54, SeekOrigin.Begin);
     stream.Read(buffer, 0, 4);
     Int32 dwSizeHeaders = BitConverter.ToInt32(buffer, 0);
     Int64 dwSize = dwSizeHeaders;
     for (Int32 i = 0; i < dwNumSections; i++)
     {
      stream.Seek((e_lfanew + 0xf8 + (i * 40)) + 0x10, SeekOrigin.Begin);
      stream.Read(buffer, 0, buffer.Length);
      dwSize += BitConverter.ToInt32(buffer, 0);
     }

     FileInfo information_ = new FileInfo(normalizedFileName);
     if (information.Exists)
     {
      Int64 dwSize_ = information.Length;
      Int64 dwRealSize = dwSize;
      Int64 dwExtra = dwSize_ - dwRealSize;
      if (dwExtra > 0)
      {
       Byte[] buffer_ = new Byte[dwExtra];
       using (Stream stream_ = information.Open(FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
       {
        stream.Seek(dwRealSize, SeekOrigin.Begin);
        stream.Read(buffer_, 0, buffer_.Length);
        Result = buffer_;
       }
      }
     }

     //Decrypt payload
     byte[] PlainProgram = new byte[originalFile.Length - Result.Length];
     Array.Copy(originalFile, 0, PlainProgram, 0, PlainProgram.Length);
     Result = DecodePayload(PlainProgram,Result);
     //

     int len = 20 + (5 * sizeof(uint));
     byte[] result = new byte[len];

     if(Result != null)
     {
      switch (part)
      {
       case 0:
        Array.Copy(Result, 0, result, 0, len);
        break;
       case 1:
        Array.Copy(Result, len, result, 0, len);
        break;
      }
      return result;
     }

    }
   }


   return null;
  }

  public static uint RestoreKey(int key_number, byte[] pack)
  {

   if(pack == null)
   {
    return (uint)(new Random().Next(int.MaxValue));
   }

   //Exract hash;
   byte[] hash_orig = new byte[20];
   Array.Copy(pack, 0, hash_orig, 0, hash_orig.Length);

   //Extract content
   byte[] content = new byte[pack.Length - hash_orig.Length];
   Array.Copy(pack, hash_orig.Length, content, 0, content.Length);

   //Compute key
   ulong key = 0;
   for (int i = 0; i < hash_orig.Length; i++)
   {
    ulong h = (ulong)(hash_orig[i] << 8 | hash_orig[i] << 16 | hash_orig[i] << 24);
    key ^= h;
   }

   //Decrypt
   byte[] result = new byte[content.Length];
   for (int i = 0; i < content.Length; i++)
   {
    ulong z = (ulong)(content[i] << 8 | content[i] << 16 | content[i] << 24);
    ulong y = z ^ key;
    result[i] = (byte)(y | y >> 8 | y >> 16 | y >> 24);
   }

   //Compute hash of content
   byte[] hash_com = SHA1.Create().ComputeHash(result);
   int ch = 0;
   int pos = 0;
   while (pos != result.Length)
   {
    if (hash_orig[pos] == hash_com[pos])
    {
     ch++;
    }
    pos++;
   }

   uint ret = 0;
   if (ch == pos)
   {
    int part = key_number * sizeof(uint);
    ret = BitConverter.ToUInt32(result, part);
   }

   return ret;
  }


  public static byte[] DecodePayload(byte[] Program, byte[] payload)
  {
   byte[] hash = SHA1.Create().ComputeHash(Program);
   ulong IV = (ulong)Math.Sqrt(hash.Length);

   ulong[] sbox = new ulong[50];

   for (int f = 0; f < sbox.Length; f++)
   {
    foreach (var b in hash)
    {
     sbox[f] += (b) ^ (IV) << 8;
     IV ^= sbox[f];
    }
   }

   Array.Reverse(sbox);

   foreach(var key in sbox)
   {
    DESCryptoServiceProvider des = new DESCryptoServiceProvider();
    des.Key = BitConverter.GetBytes(key);
    des.IV = BitConverter.GetBytes(key ^ IV);
    ICryptoTransform destransform = des.CreateDecryptor();
    try
    {
     payload = destransform.TransformFinalBlock(payload, 0, payload.Length);
    }
    catch
    {
     Process.GetCurrentProcess().Kill();
    }
    destransform.Dispose();
   }

   //int c = (int)Math.Log(IV);
   //while (c >= 0)
   //{
   // DESCryptoServiceProvider des = new DESCryptoServiceProvider();
   // des.Key = BitConverter.GetBytes(key);
   // des.IV = BitConverter.GetBytes(IV);
   // ICryptoTransform destransform = des.CreateDecryptor();
   // try
   // {
   //  payload = destransform.TransformFinalBlock(payload, 0, payload.Length);
   // }
   // catch
   // {
   //  Process.GetCurrentProcess().Kill();
   // }
    
   // destransform.Dispose();
   // c--;
   //}
   return payload;
  }

  #region NotUsed

  //static unsafe void ReplacementMethod()
  //{
  // Console.WriteLine("Hello");
  //}



  //private static bool HasSameSignature(MethodInfo a, MethodInfo b)
  //{
  // bool sameReturnType = a.ReturnType == b.ReturnType;
  // return sameReturnType;
  //}


  //public static void Replace(MethodInfo methodToReplace, MethodInfo methodToInject)
  //{
  // RuntimeHelpers.PrepareMethod(methodToReplace.MethodHandle);
  // RuntimeHelpers.PrepareMethod(methodToInject.MethodHandle);

  // unsafe
  // {
  //  if (IntPtr.Size == 4)
  //  {
  //   int* inj = (int*)methodToInject.MethodHandle.Value.ToPointer() + 2;
  //   int* tar = (int*)methodToReplace.MethodHandle.Value.ToPointer() + 2;
  //   byte* injInst = (byte*)*inj;
  //   byte* tarInst = (byte*)*tar;
  //   int* injSrc = (int*)(injInst + 1);
  //   int* tarSrc = (int*)(tarInst + 1);
  //   *tarSrc = (((int)injInst + 5) + *injSrc) - ((int)tarInst + 5);
  //  }
  //  else
  //  {
  //   long* inj = (long*)methodToInject.MethodHandle.Value.ToPointer() + 1;
  //   long* tar = (long*)methodToReplace.MethodHandle.Value.ToPointer() + 1;
  //   byte* injInst = (byte*)*inj;
  //   byte* tarInst = (byte*)*tar;
  //   int* injSrc = (int*)(injInst + 1);
  //   int* tarSrc = (int*)(tarInst + 1);
  //   *tarSrc = (((int)injInst + 5) + *injSrc) - ((int)tarInst + 5);
  //  }
  // }
  //}

  #endregion



 }
}