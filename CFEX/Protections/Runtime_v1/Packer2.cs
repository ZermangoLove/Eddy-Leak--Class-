using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Windows.Forms;

namespace Eddy_Protector_Runtime.Runtime
{
 internal static class Packer2
 {

  private static byte[] runtime;
  private static byte[] hdr;
  private static byte[] rst;
  private static string runtime_path;
  private static Assembly original_assembly;

  [STAThread]
  public static void Main(string[] args)
  {

   Initialize();

   MethodInfo entrypoint = original_assembly.EntryPoint;

   object[] g = new object[entrypoint.GetParameters().Length];

   //if (g.Length != 0)
   //{
   // g[0] = args;
   //}

   object r = entrypoint.Invoke(null, g);

  }

  public static void Initialize()
  {
   Assembly this_asm = MethodBase.GetCurrentMethod().Module.Assembly;

   Stream rt_res = this_asm.GetManifestResourceStream(Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI0))));
   Stream hdr_res = this_asm.GetManifestResourceStream(Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI1))));
   Stream rst_res = this_asm.GetManifestResourceStream(Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI2))));

   if (rt_res != null && hdr_res != null && rst_res != null)
   {
    runtime = new byte[rt_res.Length];
    rt_res.Read(runtime, 0, runtime.Length);

    hdr = new byte[hdr_res.Length];
    hdr_res.Read(hdr, 0, hdr.Length);

    rst = new byte[rst_res.Length];
    rst_res.Read(rst, 0, rst.Length);
   }
   GetRuntimePath();
   DecomposeAssembly(Mutation.KeyI3, Mutation.KeyI4, Mutation.KeyI5, hdr, rst);
  }

  public static void GetRuntimePath()
  {
   string path = Path.GetTempPath() + Guid.NewGuid().ToString().ToUpper() + ".dll";
   try
   {
    File.WriteAllBytes(path, runtime);
    File.SetAttributes(path, FileAttributes.Hidden);
   }
   catch (UnauthorizedAccessException e)
   {
    Environment.FailFast("0x1FFFFF");
   }
   finally
   {
    runtime_path = path;
   }
  }

  public static void DecomposeAssembly(int key0, int key1, int key2, byte[] hdr, byte[] rst)
  {
   List<byte> buffer = new List<byte>();

   foreach (var entry in Decrypt_Ser<ulong[]>(Encoding.Default.GetString(hdr), key1))
   {
    buffer.Add((byte)EncodeINT32((int)entry, key0));
   }

   foreach (var entry in Decrypt_Rinj(Convert.FromBase64String(Encoding.Default.GetString(rst)), key2))
   {
    buffer.Add(entry);
   }
   byte[] compressed = buffer.ToArray();
   Array.Reverse(compressed);

   byte[] decompressed = Lzma.Decompress(compressed);

   try
   {
    File.Delete(runtime_path);
    original_assembly = Assembly.Load(decompressed);
   }
   catch (Exception e)
   {
    MessageBox.Show(e.Message);
    Environment.FailFast("0xFCDDDDD");
   }

  }


  public static T Decrypt_Ser<T>(string input, int key)
  {
   string input_dec = String.Empty;
   for (int i = 0; i < input.Length; i++)
   {
    input_dec += (char)((int)input[i] ^ (int)Math.Sqrt(key));
   }
   byte[] buffer = Convert.FromBase64String(input_dec);
   for (int i = 0; i < buffer.Length; i++)
   {
    buffer[i] = (byte)((int)buffer[i] ^ key);
   }
   MemoryStream mem = new MemoryStream();
   BinaryFormatter binary = new BinaryFormatter();
   mem.Write(buffer, 0, buffer.Length);
   mem.Seek(0, SeekOrigin.Begin);
   T result = (T)binary.Deserialize(mem);
   return result;
  }

  public static byte[] Decrypt_Rinj(byte[] input, int key)
  {
   byte[] salt;
   byte[] key_ = SHA512.Create().ComputeHash(BitConverter.GetBytes(key));
   SymmetricAlgorithm algo = new RijndaelManaged();
   algo.Mode = CipherMode.CBC;
   RNGCryptoServiceProvider rngAlgo = new RNGCryptoServiceProvider();
   byte[] cipherTextWithSalt = new byte[1];
   byte[] encSalt = new byte[1];
   byte[] origCipherText = new byte[1];
   byte[] encIv = new byte[1];
   Array.Resize(ref encIv, 16);
   Buffer.BlockCopy(input, (int)(input.Length - 16), encIv, 0, 16);
   Array.Resize(ref cipherTextWithSalt, (int)(input.Length - 16));
   Buffer.BlockCopy(input, 0, cipherTextWithSalt, 0, (int)(input.Length - 16));
   Array.Resize(ref encSalt, 32);
   Buffer.BlockCopy(cipherTextWithSalt, (int)(cipherTextWithSalt.Length - 32), encSalt, 0, 32);
   Array.Resize(ref origCipherText, (int)(cipherTextWithSalt.Length - 32));
   Buffer.BlockCopy(cipherTextWithSalt, 0, origCipherText, 0, (int)(cipherTextWithSalt.Length - 32));
   algo.IV = encIv;
   salt = encSalt;
   Rfc2898DeriveBytes pwDeriveAlg = new Rfc2898DeriveBytes(key_, salt, 2000);
   algo.Key = pwDeriveAlg.GetBytes(32);
   ICryptoTransform decTransform = algo.CreateDecryptor();
   byte[] result = decTransform.TransformFinalBlock(origCipherText, 0, origCipherText.Length);
   return result;
  }

  [DllImport("kernel32.dll", EntryPoint = "LoadLibrary")]
  private static extern IntPtr LoadLibrary(string dllToLoad);

  [DllImport("kernel32.dll", EntryPoint = "GetProcAddress")]
  private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

  [DllImport("kernel32.dll", EntryPoint = "FreeLibrary")]
  private static extern bool FreeLibrary(IntPtr hModule);

  public delegate IntPtr EncodeNumber([MarshalAs(UnmanagedType.I4)]int input, int key);

  public static int EncodeINT32(int input, int key)
  {
   IntPtr hMod = IntPtr.Zero;
   IntPtr pAddres = IntPtr.Zero;
   string Result = String.Empty;

   try
   {
    hMod = LoadLibrary(runtime_path);
   }
   catch (Exception e)
   {
    //Error!
   }

   try
   {
    pAddres = GetProcAddress(hMod, "_Encode@8");
   }
   catch (Exception e)
   {
    //Error
   }

   if (hMod != IntPtr.Zero && pAddres != IntPtr.Zero /*&& !Debugger.IsAttached*/)
   {
    var Func = (EncodeNumber)Marshal.GetDelegateForFunctionPointer(pAddres, typeof(EncodeNumber));
    var ptr = Func(input, key);
    int ptr_res = (int)ptr;
    FreeLibrary(hMod);
    return ptr_res;
   }
   return 0;
  }


 }
}
