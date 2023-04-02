using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using System.Security.Cryptography;
using dnlib.DotNet.Emit;
using System.IO;
using dnlib.DotNet.Writer;

namespace Eddy_Protector_Protections.Protections.Prepacker
{
 public class PrepackerProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;

  public override string Description => "This protection can protect assembly with ILP & Themida -> Make RUNPE";

  public override string Id => Author + ".Prepacker";

  public override string Name => "Prepacker";

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

  public byte[] GetAssemblyBuffer(Context ctx)
  {
   //ctx.CurrentModule.Kind = ModuleKind.NetModule;
   MemoryStream memory = new MemoryStream();
   var opts = new ModuleWriterOptions(ctx.CurrentModule);
   opts.Logger = DummyLogger.NoThrowInstance;
   ctx.CurrentModule.Write(memory, (ModuleWriterOptions)opts);
   byte[] inputModule = memory.ToArray();
   return inputModule;
  }

  public void InjectPhase(Context ctx)
  {

   byte[] assembly = GetAssemblyBuffer(ctx);
   var secured = new Prepacker().Prepack(assembly); //ILP & Themida
   var compressed = new Compression().Compress(secured); //Compress

   var data_id = ctx.generator.RandomInt();
   var data_id_name = Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(data_id)));

   ModuleDef stubModule = CreateStubModule(ctx);

   TypeDefUser NewType = new TypeDefUser(ctx.generator.GenerateNewNameChinese(),
ctx.CurrentModule.CorLibTypes.Object.TypeDefOrRef);
   NewType.Attributes = TypeAttributes.NotPublic |
    TypeAttributes.AutoLayout |
        TypeAttributes.Class |
        TypeAttributes.AnsiClass;
   stubModule.Types.Add(NewType);


   var rtType = Utils.GetRuntimeType("Eddy_Protector_Runtime.Runtime.PrePacker");
   IEnumerable<IDnlibDef> defs = InjectHelper.Inject(rtType, NewType, stubModule);

   MethodDef entryPoint = defs.OfType<MethodDef>().Single(method => method.Name == "Main");
   entryPoint.Name = ctx.generator.GenerateNewNameChinese();
   stubModule.EntryPoint = entryPoint;

   MethodDef getDataMEthod = defs.OfType<MethodDef>().Single(method => method.Name == "GetData");


   List<Instruction> instrs = getDataMEthod.Body.Instructions.ToList();
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

   stubModule.Resources.Add(new EmbeddedResource(data_id_name, compressed,
    ManifestResourceAttributes.Private));


   MutationHelper.InjectKeys(getDataMEthod, new int[] { 0 }, new int[] {data_id});


   MemoryStream memory_final = new MemoryStream();
   var writer = new ModuleWriterOptions(stubModule);
   writer.Logger = DummyLogger.NoThrowInstance;
   stubModule.Write(memory_final, (ModuleWriterOptions)writer);

   ctx.CurrentModule = ModuleDefMD.Load(memory_final.ToArray());


  }

 }
}
