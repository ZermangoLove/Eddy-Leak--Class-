using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System.Security.Cryptography;
using dnlib.DotNet.Emit;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;

namespace Eddy_Protector_Protections.Protections.Packer
{

 /* Helpers */
 public class Helpers
 {
  public string Encrypt<T>(T input, int key)
  {
   BinaryFormatter binary = new BinaryFormatter();
   MemoryStream mem = new MemoryStream();
   binary.Serialize(mem, input);
   byte[] buffer = mem.ToArray();
   for (int i = 0; i < buffer.Length; i++)
   {
    buffer[i] = (byte)((int)buffer[i] ^ key);
   }
   string buffer_str = Convert.ToBase64String(buffer);
   string result = String.Empty;

   for (int i = 0; i < buffer_str.Length; i++)
   {
    result += (char)((int)buffer_str[i] ^ (int)Math.Sqrt(key));
   }
   return result;
  }
 }
 class DynamicNumberEncoder
 {
  [DllImport("kernel32.dll")]
  private static extern IntPtr LoadLibrary(string dllToLoad);

  [DllImport("kernel32.dll")]
  private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

  [DllImport("kernel32.dll")]
  private static extern bool FreeLibrary(IntPtr hModule);

  public delegate IntPtr EncodeNumber([MarshalAs(UnmanagedType.I4)]int input, int key);

  public int EncodeINT32(int input, int key)
  {
   IntPtr hMod = IntPtr.Zero;
   IntPtr pAddres = IntPtr.Zero;
   string Result = String.Empty;

   try
   {
    hMod = LoadLibrary("Library_debug.dll");
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


 }
 public class RijadelCustom
 {
  public byte[] Encrypt(byte[] input, int key)
  {
   byte[] key_ = SHA512.Create().ComputeHash(BitConverter.GetBytes(key));
   var symmetricAlgorithm = new RijndaelManaged();
   var rNGCryptoServiceProvider = new RNGCryptoServiceProvider();
   symmetricAlgorithm.Mode = CipherMode.CBC;
   symmetricAlgorithm.GenerateIV();
   byte[] array = new byte[32];
   rNGCryptoServiceProvider.GetBytes(array);
   var rfc2898DeriveBytes = new Rfc2898DeriveBytes(key_, array, 2000);
   symmetricAlgorithm.Key = rfc2898DeriveBytes.GetBytes(32);
   ICryptoTransform cryptoTransform = symmetricAlgorithm.CreateEncryptor();
   byte[] array2 = cryptoTransform.TransformFinalBlock(input, 0, input.Length);
   int dstOffset = array2.Length;
   Array.Resize<byte>(ref array2, array2.Length + array.Length);
   Buffer.BlockCopy(array, 0, array2, dstOffset, array.Length);
   dstOffset = array2.Length;
   Array.Resize<byte>(ref array2, array2.Length + symmetricAlgorithm.IV.Length);
   Buffer.BlockCopy(symmetricAlgorithm.IV, 0, array2, dstOffset, symmetricAlgorithm.IV.Length);
   return array2;
  }
 }
 /* ------------------------------------ */

 public class PackerProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Pack assembly";
  public override string Id => Author + ".Packer";
  public override string Name => "Packer";


  public override void Execute(Context ctx)
  {
   InjectPhase(ctx);
  }

  void ImportAssemblyTypeReferences(ModuleDef originModule, ModuleDef stubModule)
  {
   var assembly = stubModule.Assembly;
   foreach (var ca in assembly.CustomAttributes)
   {
    if (ca.AttributeType.Scope == originModule)
     ca.Constructor = (ICustomAttributeType)stubModule.Import(ca.Constructor);
   }
   foreach (var ca in assembly.DeclSecurities.SelectMany(declSec => declSec.CustomAttributes))
   {
    if (ca.AttributeType.Scope == originModule)
     ca.Constructor = (ICustomAttributeType)stubModule.Import(ca.Constructor);
   }
  }
  public ModuleDef CreateStubModule(Context ctx)
  {
   ModuleDefMD originModule = ctx.CurrentModule;
   var stubModule = new ModuleDefUser(originModule.Name, originModule.Mvid, new AssemblyRefUser(new AssemblyNameInfo(typeof(int).Assembly.GetName().FullName)));
   stubModule.Characteristics = originModule.Characteristics;
   stubModule.Cor20HeaderFlags = originModule.Cor20HeaderFlags;
   stubModule.Cor20HeaderRuntimeVersion = originModule.Cor20HeaderRuntimeVersion;
   stubModule.DllCharacteristics = originModule.DllCharacteristics;
   stubModule.EncBaseId = originModule.EncBaseId;
   stubModule.EncId = originModule.EncId;
   stubModule.Generation = originModule.Generation;
   stubModule.Kind = ModuleKind.Windows;
   stubModule.Machine = originModule.Machine;
   stubModule.RuntimeVersion = originModule.RuntimeVersion;
   stubModule.TablesHeaderVersion = originModule.TablesHeaderVersion;
   stubModule.Win32Resources = originModule.Win32Resources;
   var ver = ctx.CurrentModule.Assembly.Version;
   int major = ver.Major;
   int minor = ver.Minor;
   int build = ver.Build;
   int rev = ver.Revision;
   new AssemblyDefUser(ctx.CurrentModule.Name, new Version(major, minor, build, rev)).Modules.Add(stubModule);
   ImportAssemblyTypeReferences(originModule, stubModule);
   foreach (var attrib in ctx.CurrentModule.Assembly.CustomAttributes)
   {
    stubModule.Assembly.CustomAttributes.Add(attrib);
   }
   return stubModule;
  }



  public byte[] GetRC4Decryptor(Context ctx)
  {
   return File.ReadAllBytes("Library_debug.dll");
  }

  static int RandomInt()
  {
   byte[] buff = new byte[sizeof(int)];
   new RNGCryptoServiceProvider().GetBytes(buff);
   return BitConverter.ToInt32(buff, 0);
  }

  public byte[] GetAssemblyBuffer(Context ctx)
  {
   ctx.CurrentModule.Kind = ModuleKind.NetModule;
   MemoryStream memory = new MemoryStream();
   ctx.CurrentModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;
   ctx.CurrentModule.Write(memory, (ModuleWriterOptions)ctx.CurrentModuleWriterOptions);
   byte[] inputModule = memory.ToArray();
   return inputModule;
  }

  public void DecomposeAssembly(Context ctx, out int[] keys , out byte[] hdr_encrypted_res, out byte[] rst_encrypted_res)
  {

   keys = new int[3];

   //KEYS GENERATE
   int MutationKey0 = Math.Abs(RandomInt());
   int MutationKey1 = (int)Math.Log(Math.Abs(RandomInt()));
   int MutationKey2 = Math.Abs(RandomInt());

   keys[0] = MutationKey0;
   keys[1] = MutationKey1;
   keys[2] = MutationKey2;

   var helpers = new Helpers();
   var cypher = new RijadelCustom();
   var encoder = new DynamicNumberEncoder();

   int hdr_lenght = new Random().Next(50,100);
   byte[] assembly = GetAssemblyBuffer(ctx);

   ///assembly -> LZMA

   byte[] compressed = new Compression().Compress(assembly, null); 

   Array.Reverse(compressed);

   byte[] hdr = compressed.Take(hdr_lenght).ToArray();
   byte[] rst = compressed.Skip(hdr_lenght).Take(compressed.Length - hdr_lenght).ToArray();

   ulong[] hdr_encoded = new ulong[hdr_lenght];
   for (int f = 0; f < hdr_lenght; f++)
   {
    hdr_encoded[f] = (ulong)encoder.EncodeINT32((int)hdr[f], MutationKey0);
   }

   string hdr_encrypted = helpers.Encrypt<ulong[]>(hdr_encoded, MutationKey1);
   string rst_encrypted = Convert.ToBase64String(cypher.Encrypt(rst, MutationKey2));

   hdr_encrypted_res = Encoding.Default.GetBytes(hdr_encrypted);
   rst_encrypted_res = Encoding.Default.GetBytes(rst_encrypted);


  }

  public void InjectResources(ModuleDef stubModule, byte[] header_encrypted, byte[] rest_of_assembly_encrypted, byte[] native_decoder_stub, string header_encrypted_name, string rest_of_assembly_encrypted_name, string native_decoder_stub_name)
  {
   stubModule.Resources.Add(new EmbeddedResource(header_encrypted_name, header_encrypted,
       ManifestResourceAttributes.Private));

   stubModule.Resources.Add(new EmbeddedResource(rest_of_assembly_encrypted_name, rest_of_assembly_encrypted,
       ManifestResourceAttributes.Private));

   stubModule.Resources.Add(new EmbeddedResource(native_decoder_stub_name, native_decoder_stub,
       ManifestResourceAttributes.Private));
  }


  public void InjectPhase(Context ctx)
  {

   #region NOTUSED
   //ctx.CurrentModule.Kind = ModuleKind.NetModule;
   //MemoryStream memory = new MemoryStream();
   //ctx.CurrentModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;
   //ctx.CurrentModule.Write(memory, (ModuleWriterOptions)ctx.CurrentModuleWriterOptions);
   //byte[] inputModule = memory.ToArray();

   //var compression = new Compression();
   //byte[] CompressedModule = compression.Compress(inputModule, null);

   //var rc4 = new DynamiCyphering();
   //int encoding_key_number = ctx.generator.RandomInt();
   //string encoding_key = Convert.ToBase64String(SHA1.Create().ComputeHash(BitConverter.GetBytes(encoding_key_number)));
   //string CompressedModuleB64 = Convert.ToBase64String(CompressedModule);
   //string encoded_data = rc4.EncryptRC4(CompressedModuleB64, encoding_key);
   //string decoded_data = rc4.DecryptRC4(encoded_data, encoding_key);
   //byte[] EncryptedModule = Encoding.Default.GetBytes(encoded_data);
   #endregion

   int[] keys;
   byte[] hdr;
   byte[] rst;

   DecomposeAssembly(ctx, out keys, out hdr, out rst);

   int hdr_ID = ctx.generator.RandomInt();
   int rst_ID = ctx.generator.RandomInt();
   int rt_ID = ctx.generator.RandomInt();

   ModuleDef stubModule = CreateStubModule(ctx);

   TypeDefUser NewType = new TypeDefUser(ctx.generator.GenerateNewNameChinese(),
ctx.CurrentModule.CorLibTypes.Object.TypeDefOrRef);
   NewType.Attributes = TypeAttributes.NotPublic |
    TypeAttributes.AutoLayout |
        TypeAttributes.Class |
        TypeAttributes.AnsiClass;
   stubModule.Types.Add(NewType);


   var rtType = Utils.GetRuntimeType("Eddy_Protector_Runtime.Runtime.Packer2");
   IEnumerable<IDnlibDef> defs = InjectHelper.Inject(rtType, NewType, stubModule);

   MethodDef entryPoint = defs.OfType<MethodDef>().Single(method => method.Name == "Main");
   entryPoint.Name = ctx.generator.GenerateNewNameChinese();
   stubModule.EntryPoint = entryPoint;

   MethodDef decomposer = defs.OfType<MethodDef>().Single(method => method.Name == "DecomposeAssembly");


   List<Instruction> instrs = decomposer.Body.Instructions.ToList();
   var comp = new Compression();
   for (int i = 0; i < instrs.Count; i++)
   {
    Instruction instr = instrs[i];
    if (instr.OpCode == OpCodes.Call)
    {
     var method = (IMethod)instr.Operand;

     if (method.DeclaringType.Name == "Lzma" &&
              method.Name == "Decompress")
     {
      MethodDef decomp = comp.GetRuntimeDecompressor(ctx, stubModule, member => { });
      instr.Operand = decomp;
     }
    }
   }


   string hdr_name = Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(hdr_ID)));

   string rst_name = Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(rst_ID)));

   string rt_name = Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(rt_ID)));

   byte[] rt_stub = GetRC4Decryptor(ctx);

   InjectResources(stubModule, hdr, rst, rt_stub, hdr_name, rst_name, rt_name);


   MethodDef GetDataMethod = defs.OfType<MethodDef>().Single(method => method.Name == "Initialize");
   GetDataMethod.Name = ctx.generator.GenerateNewNameChinese();

   MutationHelper.InjectKeys(GetDataMethod, new int[] {0,1,2,3,4,5}, new int[] { rt_ID , hdr_ID , rst_ID , keys[0], keys[1], keys[2] });


   MemoryStream memory_final = new MemoryStream();
   var writer = new ModuleWriterOptions(stubModule);
   writer.Logger = DummyLogger.NoThrowInstance;
   stubModule.Write(memory_final, (ModuleWriterOptions)writer);

   ctx.CurrentModule = ModuleDefMD.Load(memory_final.ToArray());

  }

 }
}
