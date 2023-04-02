using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Linq;
//using System.Windows.Forms;

namespace Protector.Runtime
{
 internal static class Packer2
 {

  private static byte[] runtime;
  private static string runtime_path;
  private static Assembly original_assembly;
  private static int BLOBKEY = 0;

  [STAThread]
  static void Main(string[] args)
  {

   if (args[0] != null)
   {
    BLOBKEY = BitConverter.ToInt32(Convert.FromBase64String(args[0]), 0);

    Initialize();

    MethodInfo entrypoint = original_assembly.EntryPoint;

    object[] g = new object[entrypoint.GetParameters().Length];

    //if (g.Length != 0)
    //{
    // g[0] = args;
    //}

    object r = entrypoint.Invoke(null, g);

   }
   

  }

  public static void Initialize()
  {
   Assembly this_asm = MethodBase.GetCurrentMethod().Module.Assembly;

   string id =null;
   byte[] hash = SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI0));

   foreach(var h in hash)
   {
    id += h.ToString("x2").ToUpper();
   }
   Stream blobStream = this_asm.GetManifestResourceStream(id);
   byte[] blob = new byte[blobStream.Length];
   blobStream.Read(blob, 0, blob.Length);
   BLOB_Reader reader = new BLOB_Reader(blob,BLOBKEY);//Blob key

   byte[] hdr = reader.GetData(0);
   byte[] rst = reader.GetData(1);
   runtime = reader.GetData(2);

   GetRuntimePath();
   DecomposeAssembly(Mutation.KeyI1, Mutation.KeyI2, Mutation.KeyI3, hdr, rst);
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

  /// <summary>
  /// 
  /// </summary>
  /// <param name="key0">Native number encoder key</param>
  /// <param name="key1">Deserialzer key</param>
  /// <param name="key2">Rijndael key</param>
  /// <param name="hdr">header</param>
  /// <param name="rst">rest of  assembly</param>
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

   }

  } //Dalších 5 šifer

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
  } //Serializační šifra

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
  } //Modded rijndael

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
  } //nativní šifra

  class BLOB_Reader
  {

   public int dataParts;
   private int bytesReaded;
   private int blobKey;
   private byte[] blobBinary;
   private List<byte[]> DataStored;

   private BLOBHEADER header;

   internal struct BLOBHEADER
   {
    internal int headerLenght;
    internal int dataParts;
    internal List<int> dataLenght;
    internal List<int> dataEntries;
   }

   public BLOB_Reader(byte[] b, int k)
   {
    header.dataEntries = new List<int>();
    blobKey = k;
    blobBinary = b;
    DecryptBlob();
    RecorverHeader();
    ReconstructData();
   }

   private void DecryptBlob()
   {
    blobBinary = Decrypt(blobBinary, blobKey);
    DataStored = new List<byte[]>();
   }

   private void RecorverHeader()
   {
    /*HEADER RECOVERY*/
    int magic = sizeof(int);
    int sz = BitConverter.ToInt32(blobBinary.Take(magic).ToArray(), 0);
    int[] lh = new int[sz];
    int pos = magic;
    for (int f = 0; f < sz; f++)
    {
     byte[] buff = new byte[magic];
     for (int j = 0; j < magic; j++)
     {
      buff[j] = blobBinary[pos];
      pos++;
     }
     lh[f] = BitConverter.ToInt32(buff, 0);
     header.dataEntries.Add(f);
    }
    header.dataParts = sz;
    header.headerLenght = pos;
    header.dataLenght = lh.ToList();
    dataParts = header.dataParts;
   }

   private void ReconstructData()
   {
    foreach (var part in header.dataEntries)
    {
     DataStored.Add(GetPart(part));
    }
   }

   private byte[] GetPart(int part)
   {
    int dataLenght = header.dataLenght.ElementAt(part);
    byte[] buffer = new byte[dataLenght];
    int srcPos = header.headerLenght + bytesReaded;
    try
    {
     Array.Copy(blobBinary, srcPos, buffer, 0, dataLenght);
     bytesReaded += dataLenght;
     buffer = DecryptChunk(buffer, buffer.Length);
    }
    catch
    {
     throw new Exception("Data corrupted!");
    }
    return buffer;
   }

   public byte[] GetData(int ID)
   {
    if (header.dataEntries.Contains(ID))
    {
     return DataStored.ElementAt(ID);
    }
    throw new Exception("We not have data with this ID!");
   }

   private byte[] DecryptChunk(byte[] data, int key)
   {
    List<ulong> d_0 = new List<ulong>(); //P1
    ulong[] i = SHA1.Create().ComputeHash(BitConverter.GetBytes(key)).Select(b => (ulong)(b << 8 | b << 16 | b << 24)).ToArray();
    ulong[] u = data.Select(b => (ulong)(b << 8 | b << 16 | b << 24)).ToArray();
    foreach (ulong ul in u)
    {
     ulong o = 0;
     foreach (ulong iv in i)
     {
      o ^= iv;
     }
     o = o ^ ul;
     d_0.Add(o);
    }
    return d_0.Select(b => (byte)(b | (b >> 8) | (b >> 16) | (b >> 24))).ToArray();
   }

   private byte[] Decrypt(byte[] input, int key)
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

  }


 }
}
