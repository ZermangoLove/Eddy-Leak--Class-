using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using dnlib.DotNet.MD;
using System.IO;
using Eddy_Protector_Ciphering;
using dnlib.DotNet.Emit;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Eddy_Protector_Protections.Protections.Compressor
{
 public class CompressorProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "An adopted packer from ConfuserEx";
  public override string Id => Author + ".Compressor";
  public override string Name => "Compressor";

  public CompressorContext compressorContext;

  public override void Execute(Context ctx)
  {
   ExtractPhase(ctx);
   PackPhase(ctx);
  }

  public void GenerateStubName(Context ctx, out string stubName, out int y, out int c, out int w)
  {
   y = Math.Abs(ctx.generator.RandomInt()) % 50; //Mutation.KeyI3; //Number of repeats
   c = Math.Abs(ctx.generator.RandomInt()); //Mutation.KeyI4; //Initial vector
   w = Math.Abs(ctx.generator.RandomInt()); //Mutation.KeyI5; //Modulus for XOR

   stubName = String.Empty;

   for (int x = 0; x < y; x++)
   {
    int num = (int)Math.Log((c ^ w) ^ (w)) << (int)(x + 1);
    stubName += (char)num;
   }

   //ctx.logger.Info("Stub name fo Compressor generated");



  }

  public void ExtractPhase(Context ctx)
  {
   bool isExe = ctx.CurrentModule.Kind == ModuleKind.Windows ||
                ctx.CurrentModule.Kind == ModuleKind.Console;
   if (isExe)
   {
    var context = new CompressorContext
    {
     ModuleIndex = 0,
     Assembly = ctx.CurrentModule.Assembly,
     CompatMode = false,
    };

    GenerateStubName(ctx, out context.stubName, out context.y, out context.c, out context.w);

    context.ModuleName = ctx.CurrentModule.Name;
    context.EntryPoint = ctx.CurrentModule.EntryPoint;
    context.Kind = ctx.CurrentModule.Kind;

    ctx.CurrentModule.Name = context.stubName;
    ctx.CurrentModule.EntryPoint = null;
    ctx.CurrentModule.Kind = ModuleKind.NetModule;

    compressorContext = context;

    ctx.CurrentModuleWriterListener.OnWriterEvent += new ResourceRecorder(context, ctx.CurrentModule).OnWriterEvent;

    ctx.CurrentModuleWriterOptions = new ModuleWriterOptions(ctx.CurrentModule, ctx.CurrentModuleWriterListener);

    MemoryStream memory = new MemoryStream();

    ctx.CurrentModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;

    ctx.CurrentModule.Write(memory, (ModuleWriterOptions)ctx.CurrentModuleWriterOptions);

    //ctx.CurrentModule = ModuleDefMD.Load(memory.ToArray());

   }
  }

  public void PackPhase(Context ctx)
  {

   ModuleDefMD originModule = ctx.CurrentModule;
   compressorContext.OriginModuleDef = originModule;

   var stubModule = new ModuleDefUser(compressorContext.ModuleName, originModule.Mvid, originModule.CorLibTypes.AssemblyRef);
   if (compressorContext.CompatMode)
   {
    var assembly = new AssemblyDefUser(originModule.Assembly);
    assembly.Name += ".cr";
    assembly.Modules.Add(stubModule);
   }
   else
   {
    compressorContext.Assembly.Modules.Insert(0, stubModule);
    ImportAssemblyTypeReferences(originModule, stubModule);
   }
   stubModule.Characteristics = originModule.Characteristics;
   stubModule.Cor20HeaderFlags = originModule.Cor20HeaderFlags;
   stubModule.Cor20HeaderRuntimeVersion = originModule.Cor20HeaderRuntimeVersion;
   stubModule.DllCharacteristics = originModule.DllCharacteristics;
   stubModule.EncBaseId = originModule.EncBaseId;
   stubModule.EncId = originModule.EncId;
   stubModule.Generation = originModule.Generation;
   stubModule.Kind = compressorContext.Kind;
   stubModule.Machine = originModule.Machine;
   stubModule.RuntimeVersion = originModule.RuntimeVersion;
   stubModule.TablesHeaderVersion = originModule.TablesHeaderVersion;
   stubModule.Win32Resources = originModule.Win32Resources;

   InjectStub(ctx, compressorContext, stubModule);

   using (var ms = new MemoryStream())
   {
    var writeOpts = new ModuleWriterOptions(stubModule, new KeyInjector(compressorContext));
    writeOpts.MetaDataOptions.Flags = MetaDataFlags.PreserveAll;

    //writeOpts.Logger = ctx.CurrentModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;

    stubModule.Write(ms, writeOpts);

    byte[] Result = ms.ToArray();

    ctx.PackedModule = Result;

    //ctx.CurrentModule = ModuleDefMD.Load(Result);

    //File.WriteAllBytes("Packed___.exe",Result);
    
   }
  }


  public void InjectStub(Context ctx, CompressorContext compCtx, ModuleDef stubModule)
  {
   RandomGenerator random = new RandomGenerator(ctx.generator.RandomBytes(32));
   var comp = new Compression();

   var rtType = Utils.GetRuntimeType(compCtx.CompatMode ? "Eddy_Protector_Runtime.CompressorCompat" : "Eddy_Protector_Runtime.Compressor");
   IEnumerable<IDnlibDef> defs = InjectHelper.Inject(rtType, stubModule.GlobalType, stubModule);


   compCtx.Deriver = new DynamicDeriver();

   compCtx.Deriver.Init(random);

   // Main
   MethodDef entryPoint = defs.OfType<MethodDef>().Single(method => method.Name == "Main");
   stubModule.EntryPoint = entryPoint;

   if (compCtx.EntryPoint.HasAttribute("System.STAThreadAttribute"))
   {
    var attrType = stubModule.CorLibTypes.GetTypeRef("System", "STAThreadAttribute");
    var ctorSig = MethodSig.CreateInstance(stubModule.CorLibTypes.Void);
    entryPoint.CustomAttributes.Add(new CustomAttribute(
     new MemberRefUser(stubModule, ".ctor", ctorSig, attrType)));
   }
   else if (compCtx.EntryPoint.HasAttribute("System.MTAThreadAttribute"))
   {
    var attrType = stubModule.CorLibTypes.GetTypeRef("System", "MTAThreadAttribute");
    var ctorSig = MethodSig.CreateInstance(stubModule.CorLibTypes.Void);
    entryPoint.CustomAttributes.Add(new CustomAttribute(
     new MemberRefUser(stubModule, ".ctor", ctorSig, attrType)));
   }


   ctx.CurrentModuleWriterOptions = new ModuleWriterOptions(ctx.CurrentModule, ctx.CurrentModuleWriterListener);

   MemoryStream memory = new MemoryStream();

   ctx.CurrentModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;

   ctx.CurrentModule.Write(memory, (ModuleWriterOptions)ctx.CurrentModuleWriterOptions);

   uint seed = random.NextUInt32();

   compCtx.OriginModule = memory.ToArray();

   byte[] encryptedModule = compCtx.Encrypt(comp, compCtx.OriginModule, seed, null);


   compCtx.EncryptedModule = encryptedModule;

   MutationHelper.InjectKeys(entryPoint,
                             new[] { 0, 1 , 3 , 4 ,5},
                             new[] { encryptedModule.Length >> 2, (int)seed, compCtx.y , compCtx.c, compCtx.w });

   InjectData(stubModule, entryPoint, encryptedModule);


   /* Customize Decryption Method (EmitDecryp) */
   // Decrypt
   MethodDef decrypter = defs.OfType<MethodDef>().Single(method => method.Name == "Decrypt");
   decrypter.Body.SimplifyMacros(decrypter.Parameters);
   List<Instruction> instrs = decrypter.Body.Instructions.ToList();
   for (int i = 0; i < instrs.Count; i++)
   {
    Instruction instr = instrs[i];
    if (instr.OpCode == OpCodes.Call)
    {
     var method = (IMethod)instr.Operand;
     if (method.DeclaringType.Name == "Mutation" &&
         method.Name == "Crypt")
     {
      Instruction ldDst = instrs[i - 2];
      Instruction ldSrc = instrs[i - 1];
      instrs.RemoveAt(i);
      instrs.RemoveAt(i - 1);
      instrs.RemoveAt(i - 2);
      instrs.InsertRange(i - 2, compCtx.Deriver.EmitDerivation(decrypter, (Local)ldDst.Operand, (Local)ldSrc.Operand));
     }
     else if (method.DeclaringType.Name == "Lzma" &&
              method.Name == "Decompress")
     {
      MethodDef decomp = comp.GetRuntimeDecompressor(ctx,stubModule, member => { });
      //decomp.Name = ctx.generator.GenerateNewNameChinese();
      //ctx.RuntimeCompressor = decomp;
      instr.Operand = decomp;
     }
    }
   }
   decrypter.Body.Instructions.Clear();
   foreach (Instruction instr in instrs)
    decrypter.Body.Instructions.Add(instr);


   //Rename all

   foreach (var def in defs)
   {
    def.Name = ctx.generator.GenerateNewNameChinese();
   }

   // Pack modules
   PackModules(compCtx, stubModule, comp, random);
  }

  void InjectData(ModuleDef stubModule, MethodDef method, byte[] data)
  {

   var dataType = new TypeDefUser("", "DataType", stubModule.CorLibTypes.GetTypeRef("System", "ValueType"));
   dataType.Layout = TypeAttributes.ExplicitLayout;
   dataType.Visibility = TypeAttributes.NestedPrivate;
   dataType.IsSealed = true;
   dataType.ClassLayout = new ClassLayoutUser(1, (uint)data.Length);
   stubModule.GlobalType.NestedTypes.Add(dataType);

   var dataField = new FieldDefUser("DataField", new FieldSig(dataType.ToTypeSig()))
   {
    IsStatic = true,
    HasFieldRVA = true,
    InitialValue = data,
    Access = FieldAttributes.CompilerControlled
   };
   stubModule.GlobalType.Fields.Add(dataField);

   MutationHelper.ReplacePlaceholder(method, arg =>
   {
    var repl = new List<Instruction>();
    repl.AddRange(arg);
    repl.Add(Instruction.Create(OpCodes.Dup));
    repl.Add(Instruction.Create(OpCodes.Ldtoken, dataField));
    repl.Add(Instruction.Create(OpCodes.Call, stubModule.Import(
     typeof(RuntimeHelpers).GetMethod("InitializeArray"))));
    return repl.ToArray();
   });
  }

  void PackModules(CompressorContext compCtx, ModuleDef stubModule, Compression comp, RandomGenerator random)
  {
   int maxLen = 0;
   var modules = new Dictionary<string, byte[]>();

   //for (int i = 0; i < context.OutputModules.Count; i++)
   //{
   // context.Logger.Warn("Pack modules Load to outpuModule 08" + context.OutputModules[i].ToString());
   // if (i == compCtx.ModuleIndex)
   //  continue;

   // string id = GetId(context.Modules[i].Assembly);

   // context.Logger.Warn("Pack modules ID 09" + id.ToString());

   // modules.Add(id, context.OutputModules[i]);

   // int strLen = Encoding.UTF8.GetByteCount(id);
   // if (strLen > maxLen)
   //  maxLen = strLen;
   //}

   //var name_ = GetId(compressorContext.OriginModule).ToUpperInvariant();
   //modules.Add(name, extModule);

   //int strLen = Encoding.UTF8.GetByteCount(name_);
   //if (strLen > maxLen)
   // maxLen = strLen;



   //start here!
   byte[] key = random.NextBytes(4 + maxLen); //KEY
   key[0] = (byte)(compCtx.EntryPointToken >> 0);
   key[1] = (byte)(compCtx.EntryPointToken >> 8);
   key[2] = (byte)(compCtx.EntryPointToken >> 16);
   key[3] = (byte)(compCtx.EntryPointToken >> 24);
   for (int i = 4; i < key.Length; i++) // no zero bytes
    key[i] |= 1;
   compCtx.KeySig = key;

   //int moduleIndex = 0;

   //foreach (var entry in modules)
   //{
   // byte[] name = Encoding.UTF8.GetBytes(entry.Key);
   // for (int i = 0; i < name.Length; i++)
   //  name[i] *= key[i + 4];

   // uint state = 0x6fff61;
   // foreach (byte chr in name)
   //  state = state * 0x5e3f1f + chr;
   // byte[] encrypted = compCtx.Encrypt(comp, entry.Value, state, progress =>
   // {
   //  progress = (progress + moduleIndex) / modules.Count;
   // });

   // var resource = new EmbeddedResource(Convert.ToBase64String(name), encrypted, ManifestResourceAttributes.Private);
   // stubModule.Resources.Add(resource);
   // moduleIndex++;
   //}

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




 }

 class KeyInjector : IModuleWriterListener
 {
  readonly CompressorContext ctx;

  public KeyInjector(CompressorContext ctx)
  {
   this.ctx = ctx;
  }

  public void OnWriterEvent(ModuleWriterBase writer, ModuleWriterEvent evt)
  {

   if (evt == ModuleWriterEvent.MDBeginCreateTables)
   {
    // Add key signature
    uint sigBlob = writer.MetaData.BlobHeap.Add(ctx.KeySig);
    uint sigRid = writer.MetaData.TablesHeap.StandAloneSigTable.Add(new RawStandAloneSigRow(sigBlob));
    uint sigToken = 0x11000000 | sigRid;
    ctx.KeyToken = sigToken;
    MutationHelper.InjectKey(writer.Module.EntryPoint, 2, (int)sigToken);
   }
   else if (evt == ModuleWriterEvent.MDBeginAddResources && !ctx.CompatMode)
   {
    // Compute hash
    byte[] hash = SHA1.Create().ComputeHash(ctx.OriginModule);
    uint hashBlob = writer.MetaData.BlobHeap.Add(hash);

    MDTable<RawFileRow> fileTbl = writer.MetaData.TablesHeap.FileTable;
    uint fileRid = fileTbl.Add(new RawFileRow(
                                (uint)dnlib.DotNet.FileAttributes.ContainsMetaData,
                                writer.MetaData.StringsHeap.Add(ctx.stubName),
                                hashBlob));
    uint impl = CodedToken.Implementation.Encode(new MDToken(Table.File, fileRid));

    // Add resources
    MDTable<RawManifestResourceRow> resTbl = writer.MetaData.TablesHeap.ManifestResourceTable;
    foreach (var resource in ctx.ManifestResources)
     resTbl.Add(new RawManifestResourceRow(resource.Item1, resource.Item2, writer.MetaData.StringsHeap.Add(resource.Item3), impl));

    // Add exported types
    var exTbl = writer.MetaData.TablesHeap.ExportedTypeTable;
    foreach (var type in ctx.OriginModuleDef.GetTypes())
    {
     if (!type.IsVisibleOutside())
      continue;
     exTbl.Add(new RawExportedTypeRow((uint)type.Attributes, 0,
                                      writer.MetaData.StringsHeap.Add(type.Name),
                                      writer.MetaData.StringsHeap.Add(type.Namespace), impl));
    }
   }
  }
 }

 class ResourceRecorder
 {
  readonly CompressorContext ctx;
  ModuleDef targetModule;

  public ResourceRecorder(CompressorContext ctx, ModuleDef module)
  {
   this.ctx = ctx;
   targetModule = module;
  }

  public void OnWriterEvent(object sender, ModuleWriterListenerEventArgs e)
  {

   if (e.WriterEvent == ModuleWriterEvent.MDEndAddResources)
   {
    var writer = (ModuleWriterBase)sender;
    ctx.ManifestResources = new List<Tuple<uint, uint, string>>();
    Dictionary<uint, byte[]> stringDict = writer.MetaData.StringsHeap.GetAllRawData().ToDictionary(pair => pair.Key, pair => pair.Value);
    foreach (RawManifestResourceRow resource in writer.MetaData.TablesHeap.ManifestResourceTable)
     ctx.ManifestResources.Add(Tuple.Create(resource.Offset, resource.Flags, Encoding.UTF8.GetString(stringDict[resource.Name])));
    ctx.EntryPointToken = writer.MetaData.GetToken(ctx.EntryPoint).Raw;
   }
  }
 }

}
