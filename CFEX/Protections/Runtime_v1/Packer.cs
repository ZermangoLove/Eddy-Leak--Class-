using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO.Compression;

namespace Eddy_Protector_Runtime.Runtime
{
 internal static class Packer
 {

  [DllImport("kernel32.dll")]
  public static extern IntPtr LoadLibrary(string dllToLoad);
  [DllImport("kernel32.dll")]
  public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
  [DllImport("kernel32.dll")]
  public static extern bool FreeLibrary(IntPtr hModule);

  public delegate IntPtr Decrypt_([MarshalAs(UnmanagedType.AnsiBStr)]string input, string key);

  public delegate IntPtr EncodeNumber([MarshalAs(UnmanagedType.I4)]int input, int key);


  static string rt_str;
  static string hdr_str;
  static string rst_str;
  static byte[] rt_bin;

  [STAThread]
  public static void Main(string[] args)
  {
   /* KEYS
    * | 0 = Input for INT32 Encoder
    * | 1 = Key for INT32 Encoder
    * | 2 = Key for RC4 Decrypt
    */
   /* HEADER RECOVERING
    * 1) Decrypt from RC4
    * 2) Deserialize
    * 2) From ulong[] to byte[]
    */
   /* ASSEMBLY RECORVER
    * 1) Decrypt header
    * 2) Decode from B64 rest of assembly
    * 3) Join header & rest of assembly
    * 4) Decompress by LZMA
    */ 


   if(GetDataFromResources() /*&& Assembly.GetExecutingAssembly() == Assembly.GetCallingAssembly()*/)
   {
    var b = Decrypt(hdr_str, Convert.ToBase64String(BitConverter.GetBytes(Mutation.KeyI2)));
    var c = Deserialize<ulong[]>(b, NumberEncoder(Mutation.KeyI0, Mutation.KeyI1));
    var d = UlongToByte(c);
    byte[] hdr = d;

    byte[] rst = Convert.FromBase64String(rst_str);
    List<byte> assembly_plain = new List<byte>();

    for (int f = 0; f < hdr.Length; f++)
    {
     assembly_plain.Add(hdr[f]);
    }
    for (int t = 0; t < rst.Length; t++)
    {
     assembly_plain.Add(rst[t]);
    }

    byte[] assembly_decompressed = Lzma.Decompress(assembly_plain.ToArray());

    Assembly clean_assembly = Assembly.Load(assembly_decompressed);

    MethodInfo entrypoint = clean_assembly.EntryPoint;

    object[] g = new object[entrypoint.GetParameters().Length];
    if (g.Length != 0)
    {
     g[0] = args;
    }

    object r = entrypoint.Invoke(null, g);
   }
   else
   {
    //Fucking wrong!
   }
  }

  public static bool GetDataFromResources()
  {
   string rt_name = Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI0))); //Runtime C++ name
   string hdr_name = Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI1))); //Header name
   string rst_name = Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI2))); //Rest assembly name

   Assembly this_asm = MethodBase.GetCurrentMethod().Module.Assembly;

   byte[] result = new byte[0];
   
   var rt_res = this_asm.GetManifestResourceStream(rt_name);
   var hdr_res = this_asm.GetManifestResourceStream(hdr_name);
   var rst_res = this_asm.GetManifestResourceStream(rst_name);

   if (rt_res != null && hdr_res != null && rst_res != null)
   {
    byte[] rt_byte = new byte[rt_res.Length];
    rt_res.Read(rt_byte, 0, rt_byte.Length);
    rt_str = Encoding.Default.GetString(rt_byte);

    byte[] hdr_byte = new byte[hdr_res.Length];
    hdr_res.Read(hdr_byte, 0, hdr_byte.Length);
    hdr_str = Encoding.Default.GetString(hdr_byte);

    byte[] rst_byte = new byte[rst_res.Length];
    rst_res.Read(rst_byte, 0, rst_byte.Length);
    rst_str = Encoding.Default.GetString(rst_byte);
   }

   if (rt_str.Length != 0 && hdr_str.Length != 0 && rst_str.Length != 0)
   {
    rt_bin = Convert.FromBase64String(Decrypt(rt_str, Convert.ToBase64String(BitConverter.GetBytes(Mutation.KeyI3))));
    return true;   
   }
   else
   {
    return false;
   }

  }
  public static byte[] UlongToByte(ulong[] buffer)
  {
   byte[] buffer_byte = new byte[buffer.Length];

   for (int a = 0; a < buffer.Length; a++)
   {
    buffer_byte[a] = (byte)(buffer[a] | (buffer[a] >> 8) | (buffer[a] >> 16) | (buffer[a] >> 24));
   }
   return buffer_byte;
  }
  public static T Deserialize<T>(string input, int key)
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

  public static string Decrypt(string input, string Key)
  {
   byte[] key = SHA256.Create().ComputeHash(Encoding.Default.GetBytes(Key));
   byte[] cipherText = Encoding.Default.GetBytes(input);

   byte[] salt;
   SymmetricAlgorithm algo = new RijndaelManaged();
   algo.Mode = CipherMode.CBC;
   RNGCryptoServiceProvider rngAlgo = new RNGCryptoServiceProvider();
   byte[] cipherTextWithSalt = new byte[1];
   byte[] encSalt = new byte[1];
   byte[] origCipherText = new byte[1];
   byte[] encIv = new byte[1];
   Array.Resize(ref encIv, 16);
   Buffer.BlockCopy(cipherText, (int)(cipherText.Length - 16), encIv, 0, 16);
   Array.Resize(ref cipherTextWithSalt, (int)(cipherText.Length - 16));
   Buffer.BlockCopy(cipherText, 0, cipherTextWithSalt, 0, (int)(cipherText.Length - 16));
   Array.Resize(ref encSalt, 32);
   Buffer.BlockCopy(cipherTextWithSalt, (int)(cipherTextWithSalt.Length - 32), encSalt, 0, 32);
   Array.Resize(ref origCipherText, (int)(cipherTextWithSalt.Length - 32));
   Buffer.BlockCopy(cipherTextWithSalt, 0, origCipherText, 0, (int)(cipherTextWithSalt.Length - 32));
   algo.IV = encIv;
   salt = encSalt;
   Rfc2898DeriveBytes pwDeriveAlg = new Rfc2898DeriveBytes(key, salt, 2000);
   algo.Key = pwDeriveAlg.GetBytes(32);
   ICryptoTransform decTransform = algo.CreateDecryptor();
   byte[] result = decTransform.TransformFinalBlock(origCipherText, 0, origCipherText.Length);
   return Encoding.Default.GetString(result);
  }

  public static int NumberEncoder(int input, int key)
  {

   #region NOTUSED SLOW!!

   //byte[] runtime_lib_data = Convert.FromBase64String(rt_str);

   //byte[] runtime_lib_decompressed = null;

   //using (GZipStream stream = new GZipStream(new MemoryStream(runtime_lib_data),
   //            CompressionMode.Decompress))
   //{
   // const int size = 4096;
   // byte[] buffer_gzip = new byte[size];
   // using (MemoryStream memory = new MemoryStream())
   // {
   //  int count = 0;
   //  do
   //  {
   //   count = stream.Read(buffer_gzip, 0, size);
   //   if (count > 0)
   //   {
   //    memory.Write(buffer_gzip, 0, count);
   //   }
   //  }
   //  while (count > 0);
   //  runtime_lib_decompressed = memory.ToArray();
   // }
   //}

   //string runtime_libserialzed = Encoding.Default.GetString(runtime_lib_decompressed);

   //string input_dec = String.Empty;
   //for (int i = 0; i < runtime_libserialzed.Length; i++)
   //{
   // input_dec += (char)((int)runtime_libserialzed[i] ^ (int)Math.Sqrt(96));
   //}
   //byte[] buffer = Convert.FromBase64String(input_dec);
   //for (int i = 0; i < buffer.Length; i++)
   //{
   // buffer[i] = (byte)((int)buffer[i] ^ 96);
   //}
   //MemoryStream mem = new MemoryStream();
   //BinaryFormatter binary = new BinaryFormatter();
   //mem.Write(buffer, 0, buffer.Length);
   //mem.Seek(0, SeekOrigin.Begin);
   //byte[] result = (byte[])binary.Deserialize(mem);

   #endregion

   Guid id = Guid.NewGuid();
   string lib_temp_path = Path.GetTempPath() + id.ToString().ToUpper() + ".dll";

   try
   {
    File.WriteAllBytes(lib_temp_path, rt_bin);
    File.SetAttributes(lib_temp_path, FileAttributes.Hidden);
   }
   catch (Exception e)
   {
    //Err
   }

   IntPtr hMod = IntPtr.Zero;
   IntPtr pAddres = IntPtr.Zero;
   string Result = String.Empty;

   try
   {
    hMod = LoadLibrary(lib_temp_path);
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

   if (hMod != IntPtr.Zero && pAddres != IntPtr.Zero)
   {
    var Func = (EncodeNumber)Marshal.GetDelegateForFunctionPointer(pAddres, typeof(EncodeNumber));
    var ptr = Func(input, key);
    int ptr_res = (int)ptr;
    return ptr_res;
   }
   return 0;
  }





  #region OLDSTUFF

  //[DllImport("kernel32.dll")]
  //public static extern IntPtr LoadLibrary(string dllToLoad);
  //[DllImport("kernel32.dll")]
  //public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
  //[DllImport("kernel32.dll")]
  //public static extern bool FreeLibrary(IntPtr hModule);

  //public delegate IntPtr Decrypt_([MarshalAs(UnmanagedType.AnsiBStr)]string input, string key);

  //[STAThread]
  //public static void Main(string[] args)
  //{
  // byte[] result = new byte[0];
  // Assembly assembly = MethodBase.GetCurrentMethod().Module.Assembly;
  // var manifestResourceStream = assembly.GetManifestResourceStream(Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI0))));

  // if (manifestResourceStream != null)
  // {
  //  byte[] array = new byte[manifestResourceStream.Length];
  //  manifestResourceStream.Read(array, 0, array.Length);
  //  result = array;

  //  byte[] decrypted = Convert.FromBase64String(Get(Encoding.Default.GetString(result), Convert.ToBase64String(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI1)))));

  //  byte[] decompressed = Lzma.Decompress(decrypted);


  //  var asm = Assembly.Load(decompressed);


  //  var entry = asm.EntryPoint;

  //  var g = new object[entry.GetParameters().Length];
  //  if (g.Length != 0)
  //   g[0] = args;
  //  object r = entry.Invoke(null, g);



  // }
  //}

  //static string Get(string ciphertext, string key)
  //{
  // byte[] resources_lib = new byte[0];
  // Assembly assembly = MethodBase.GetCurrentMethod().Module.Assembly;
  // var manifestResourceStream = assembly.GetManifestResourceStream(Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI0))));

  // if (manifestResourceStream != null)
  // {
  //  byte[] array = new byte[manifestResourceStream.Length];
  //  manifestResourceStream.Read(array, 0, array.Length);
  //  resources_lib = array;
  // }

  //  byte[] runtime_lib_data = Convert.FromBase64String(Encoding.Default.GetString(resources_lib));

  //  byte[] runtime_lib_decompressed = null;

  //  using (GZipStream stream = new GZipStream(new MemoryStream(runtime_lib_data),
  //              CompressionMode.Decompress))
  //  {
  //   const int size = 4096;
  //   byte[] buffer_gzip = new byte[size];
  //   using (MemoryStream memory = new MemoryStream())
  //   {
  //    int count = 0;
  //    do
  //    {
  //     count = stream.Read(buffer_gzip, 0, size);
  //     if (count > 0)
  //     {
  //      memory.Write(buffer_gzip, 0, count);
  //     }
  //    }
  //    while (count > 0);
  //    runtime_lib_decompressed = memory.ToArray();
  //   }
  //  }

  //  string runtime_libserialzed = Encoding.Default.GetString(runtime_lib_decompressed);

  //  string input_dec = String.Empty;
  //  for (int i = 0; i < runtime_libserialzed.Length; i++)
  //  {
  //   input_dec += (char)((int)runtime_libserialzed[i] ^ (int)Math.Sqrt(96));
  //  }
  //  byte[] buffer = Convert.FromBase64String(input_dec);
  //  for (int i = 0; i < buffer.Length; i++)
  //  {
  //   buffer[i] = (byte)((int)buffer[i] ^ 96);
  //  }
  //  MemoryStream mem = new MemoryStream();
  //  BinaryFormatter binary = new BinaryFormatter();
  //  mem.Write(buffer, 0, buffer.Length);
  //  mem.Seek(0, SeekOrigin.Begin);
  //  byte[] result = (byte[])binary.Deserialize(mem);

  //  Guid id = Guid.NewGuid();
  //  string lib_temp_path = Path.GetTempPath() + id.ToString().ToUpper() + ".dll";

  //  try
  //  {
  //   File.WriteAllBytes(lib_temp_path, result);
  //   File.SetAttributes(lib_temp_path, FileAttributes.Hidden);
  //  }
  //  catch (Exception e)
  //  {
  //   //Err
  //  }

  //  IntPtr hMod = IntPtr.Zero;
  //  IntPtr pAddres = IntPtr.Zero;
  //  string Result = String.Empty;

  //  try
  //  {
  //   hMod = LoadLibrary(lib_temp_path);
  //  }
  //  catch (Exception e)
  //  {
  //   //Error!
  //  }

  //  try
  //  {
  //   pAddres = GetProcAddress(hMod, "_Decrypt@8");
  //  }
  //  catch (Exception e)
  //  {
  //   //Error
  //  }

  //  if (hMod != IntPtr.Zero && pAddres != IntPtr.Zero)
  //  {
  //   Decrypt_ ptr_func = (Decrypt_)Marshal.GetDelegateForFunctionPointer(pAddres, typeof(Decrypt_));
  //   IntPtr ptr = ptr_func(ciphertext, key);
  //   string ptr_res = Marshal.PtrToStringAnsi(ptr);
  //   FreeLibrary(hMod);
  //   File.Delete(lib_temp_path);
  //   return ptr_res;
  //  }
  //  return "SOMETHING WRONG, (INVALID DATA)!";
  //}

  #endregion
 }
}
