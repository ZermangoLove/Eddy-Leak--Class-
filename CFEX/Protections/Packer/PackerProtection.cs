using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System.Security.Cryptography;
using dnlib.DotNet.Emit;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;

using Protector.Helpers;
using Protector.Protections;
using Protector.Handler;
using Eddy_Protector_Core.Core;

namespace Protector.Protections.Packer
{

 /* Helpers */
 class Helpers
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
 class RijadelCustom
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

 class PackerProtection
 {

  public ModuleDef module_to_pack;
  public byte[] module_to_pack_data;

  public byte[] Protect(ModuleDef mod, byte[] compilled_module, ProtectorContext ctx)
  {
   module_to_pack = mod;
   module_to_pack_data = compilled_module;
   byte[] a = InjectPhase(ctx);
   return a;
  }

  public void DecomposeAssembly(ProtectorContext ctx, out int[] keys, out byte[] hdr_encrypted_res, out byte[] rst_encrypted_res)
  {

   keys = new int[3];

   //KEYS GENERATE
   int MutationKey0 = Math.Abs(ctx.random_generator.RandomInt());
   int MutationKey1 = (int)Math.Log(Math.Abs(ctx.random_generator.RandomInt()));
   int MutationKey2 = Math.Abs(ctx.random_generator.RandomInt());

   keys[0] = MutationKey0;
   keys[1] = MutationKey1;
   keys[2] = MutationKey2;

   var helpers = new Helpers();
   var cypher = new RijadelCustom();
   var encoder = new DynamicNumberEncoder();

   int hdr_lenght = new Random().Next(50, 100);
   byte[] assembly = module_to_pack_data;

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


  public byte[] InjectPhase(ProtectorContext ctx)
  {

   int[] keys;
   byte[] hdr;
   byte[] rst;

   int BlobKey = ctx.random_generator.RandomInt(); //Key for decrypt blob
   ctx.BlobKey = BlobKey;

   DecomposeAssembly(ctx, out keys, out hdr, out rst);
   byte[] rt_stub = GetDynamicNumberEncoder();

   List<byte[]> BlobParts = new List<byte[]>();

   BlobParts.Add(hdr);
   BlobParts.Add(rst);
   BlobParts.Add(rt_stub);

   BLOB_Creator creator = new BLOB_Creator();
   byte[] blobData = creator.CreateBlob(BlobParts,BlobKey);

   int blobIDNum = ctx.random_generator.RandomInt();
   string blobID = null;
   byte[] hash = SHA1.Create().ComputeHash(BitConverter.GetBytes(blobIDNum));

   foreach (var h in hash)
   {
    blobID += h.ToString("x2").ToUpper();
   }

   ModuleDef stubModule = CreateStubModule(ctx);

   TypeDefUser NewType = new TypeDefUser(ctx.random_generator.GenerateString(),
module_to_pack.CorLibTypes.Object.TypeDefOrRef);
   NewType.Attributes = TypeAttributes.NotPublic |
    TypeAttributes.AutoLayout |
        TypeAttributes.Class |
        TypeAttributes.AnsiClass;
   stubModule.Types.Add(NewType);

   ctx.StubType = NewType;

   var rtType = DnLibHelper.GetRuntimeType("Protector.Runtime.Packer2");
   IEnumerable<IDnlibDef> defs = InjectHelper.Inject(rtType, NewType, stubModule);

   MethodDef entryPoint = defs.OfType<MethodDef>().Single(method => method.Name == "Main");
   entryPoint.Name = ctx.random_generator.GenerateString();
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
      ctx.LzmaMethod = decomp;
     }
    }
   }


   MethodDef GetDataMethod = defs.OfType<MethodDef>().Single(method => method.Name == "Initialize");
   GetDataMethod.Name = ctx.random_generator.GenerateString();

   MutationHelper.InjectKeys(GetDataMethod, new int[] { 0, 1, 2, 3 }, new int[] { blobIDNum,keys[0], keys[1], keys[2] });

   stubModule.Resources.Add(new EmbeddedResource(blobID, blobData,
    ManifestResourceAttributes.Private));


   MemoryStream memory_final = new MemoryStream();
   var writer = new ModuleWriterOptions(stubModule);
   writer.Logger = DummyLogger.NoThrowInstance;
   stubModule.Write(memory_final, (ModuleWriterOptions)writer);

   return memory_final.ToArray();
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
  public ModuleDef CreateStubModule(ProtectorContext ctx)
  {
   ModuleDefMD originModule = (ModuleDefMD)module_to_pack;
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
   var ver = module_to_pack.Assembly.Version;
   int major = ver.Major;
   int minor = ver.Minor;
   int build = ver.Build;
   int rev = ver.Revision;
   new AssemblyDefUser(module_to_pack.Name, new Version(major, minor, build, rev)).Modules.Add(stubModule);
   ImportAssemblyTypeReferences(originModule, stubModule);
   foreach (var attrib in module_to_pack.Assembly.CustomAttributes)
   {
    stubModule.Assembly.CustomAttributes.Add(attrib);
   }
   return stubModule;
  }

  public byte[] GetDynamicNumberEncoder()
  {
   return File.ReadAllBytes("Library_release.dll");
  }

 }
}
