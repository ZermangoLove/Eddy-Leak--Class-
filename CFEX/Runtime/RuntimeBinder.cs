using Protector.Runtime;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace ProtectorRuntime.Runtime
{
 internal static class RuntimeBinder
 {

  public static void Initialize()
  {
   AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(LoadLibraryDynamic);
  }

  public static Assembly LoadLibraryDynamic(object sender, ResolveEventArgs args)
  {
   int rtNums = Mutation.KeyI0;
   //Keys
   int a = Mutation.KeyI1;
   int b = Mutation.KeyI2;
   int c = Mutation.KeyI3;


   int resIDn = (~(~(~(~(a) ^ (b) ^ (c) ^ (rtNums + sizeof(ulong))))) >> (rtNums + 1 + sizeof(short)));
   string resIDs = Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(resIDn)));
   Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resIDs);

   byte[] runtime = new byte[stream.Length];
   stream.Read(runtime, 0, runtime.Length);

   byte[] runtimeBinary = Lzma.Decompress(runtime);

   if (runtimeBinary != null)
   {
    return Assembly.Load(runtimeBinary);
   }
   return null;
  }


 }
}
