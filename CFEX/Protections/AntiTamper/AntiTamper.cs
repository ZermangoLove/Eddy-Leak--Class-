using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Protector.Utils;
using Eddy_Protector_Ciphering.AST;
using Eddy_Protector_Ciphering;
using Eddy_Protector_Ciphering.Generation;
using dnlib.IO;
using dnlib.PE;

namespace Protector
{
 public struct AntiTamperContext
 {
  public ModuleWriterListener CurrentModuleWriterListener { get; set; }
  public ModuleWriterOptions CurrentModuleWriterOptions { get; set; }

  public List<MethodDef> Targets;
 }

 class AntiTamper
 {
  AntiTamperContext ctx;
  public byte[] Protect(byte[] moduleByte)
  {
   ctx = new AntiTamperContext();
   ModuleDef mod = ModuleDefMD.Load(moduleByte);
   ctx.Targets = SearchTargets(mod);

   ctx.CurrentModuleWriterListener = new ModuleWriterListener();
   ctx.CurrentModuleWriterOptions = new ModuleWriterOptions(mod, ctx.CurrentModuleWriterListener);

   IModeHandler antitamper = new NormalMode(ctx,mod);
   antitamper.HandleInject();
   antitamper.HandleMD();


   return UpdateModule(mod);
  }

  public List<MethodDef> SearchTargets(ModuleDef module)
  {
   List<MethodDef> targets = new List<MethodDef>();

   foreach (var t in module.GetTypes())
   {
    foreach (var m in t.Methods)
    {
     if (m.HasBody && !m.IsConstructor)
     {
      targets.Add(m);
     }
    }
   }
   return targets;
  }

  public byte[] UpdateModule(ModuleDef mod)
  {
   MemoryStream output = new MemoryStream();
   ctx.CurrentModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;
   //ctx.CurrentModuleWriterOptions.MetaDataOptions.Flags = MetaDataFlags.PreserveAllMethodRids;

   if (ctx.CurrentModuleWriterOptions is ModuleWriterOptions)
   {
    try
    {
     mod.Write(output, (ModuleWriterOptions)ctx.CurrentModuleWriterOptions);
    }
    catch (Exception e)
    {

    }

   }
   return output.ToArray();
  }
 }


 internal interface IKeyDeriver
 {
  void Init(RandomGenerator random);
  uint[] DeriveKey(uint[] a, uint[] b);
  IEnumerable<Instruction> EmitDerivation(MethodDef method, Local dst, Local src);
 }

 internal interface IModeHandler
 {
  void HandleInject();
  void HandleMD();
 }

 internal class NormalMode : IModeHandler
 {

  AntiTamperContext context;

  private ModuleDef Module;

  public NormalMode(AntiTamperContext ctx, ModuleDef mod)
  {
   this.context = ctx;
   this.Module = mod;
  }

  uint mut3;
  IKeyDeriver deriver;

  List<MethodDef> methods;
  uint name1, name2;
  RandomGenerator random;
  uint mut4;
  uint mut2;
  uint mut1;

  public void HandleInject()
  {
   random = new RandomGenerator(Generator.GetBytes(32));
   mut1 = random.NextUInt32();
   mut2 = random.NextUInt32();
   mut3 = random.NextUInt32();
   mut4 = random.NextUInt32();
   name1 = random.NextUInt32() & 0x7f7f7f7f;
   name2 = random.NextUInt32() & 0x7f7f7f7f;

   deriver = new NormalDeriver();
   deriver.Init(random);

   TypeDef initType = DnLibHelper.GetRuntimeType("Runtime.AntiTamperNormal");
   IEnumerable<IDnlibDef> members = InjectHelper.Inject(initType, Module.GlobalType, Module);
   var initMethod = (MethodDef)members.Single(m => m.Name == "Initialize");

   initMethod.Body.SimplifyMacros(initMethod.Parameters);
   List<Instruction> instrs = initMethod.Body.Instructions.ToList();
   for (int i = 0; i < instrs.Count; i++)
   {
    Instruction instr = instrs[i];
    if (instr.OpCode == OpCodes.Ldtoken)
    {
     instr.Operand = Module.GlobalType;
    }
    else if (instr.OpCode == OpCodes.Call)
    {
     var method = (IMethod)instr.Operand;
     if (method.DeclaringType.Name == "Mutation" &&
         method.Name == "Crypt")
     {
      Instruction ldDst = instrs[i - 2];
      Instruction ldSrc = instrs[i - 1];
      Debug.Assert(ldDst.OpCode == OpCodes.Ldloc && ldSrc.OpCode == OpCodes.Ldloc);
      instrs.RemoveAt(i);
      instrs.RemoveAt(i - 1);
      instrs.RemoveAt(i - 2);
      instrs.InsertRange(i - 2, deriver.EmitDerivation(initMethod, (Local)ldDst.Operand, (Local)ldSrc.Operand));
     }
    }
   }
   initMethod.Body.Instructions.Clear();
   foreach (Instruction instr in instrs)
    initMethod.Body.Instructions.Add(instr);

   MutationHelper.InjectKeys(initMethod,
                             new[] { 0, 1, 2, 3, 4 },
                             new[] { (int)(name1 * name2), (int)mut1, (int)mut2, (int)mut3, (int)mut4 });

   MethodDef cctor = Module.GlobalType.FindOrCreateStaticConstructor();
   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, initMethod));


   Instruction[] ins = initMethod.Body.Instructions.ToArray();
   for (int i = 0; i < ins.Length;i++)
   {
    if (ins[i].OpCode == OpCodes.Ldc_I4)
    {
     if ((int)ins[i].Operand != 0)
     {
      GenerateExPression((int)ins[i].Operand);
     }   
    }
   }


  }

  public List<Instruction> GenerateExPression(int a)
  {

   List<int> nums = new List<int>();


   int[] derivations = new int[20]; //Repeating
   int num = (int)a;
   string result = String.Empty;

   for (int i = 1; i < derivations.Length; i++)
   {
    int variator = (int)i << 16;
    derivations[i] = num ^ variator;
    result += "(" + derivations[i].ToString() + "^" + variator.ToString() + ")^";
   }

   var ins = new List<Instruction>();

   return ins;
   
  }



  public void HandleMD()
  {
   methods = context.Targets;
   context.CurrentModuleWriterListener.OnWriterEvent += OnWriterEvent;
  }

  void OnWriterEvent(object sender, ModuleWriterListenerEventArgs e)
  {
   var writer = (ModuleWriterBase)sender;
   if (e.WriterEvent == ModuleWriterEvent.MDEndCreateTables)
   {
    CreateSections(writer);
   }
   else if (e.WriterEvent == ModuleWriterEvent.BeginStrongNameSign)
   {
    EncryptSection(writer);
   }
  }

  void CreateSections(ModuleWriterBase writer)
  {
   var nameBuffer = new byte[8];
   nameBuffer[0] = (byte)(name1 >> 0);
   nameBuffer[1] = (byte)(name1 >> 8);
   nameBuffer[2] = (byte)(name1 >> 16);
   nameBuffer[3] = (byte)(name1 >> 24);
   nameBuffer[4] = (byte)(name2 >> 0);
   nameBuffer[5] = (byte)(name2 >> 8);
   nameBuffer[6] = (byte)(name2 >> 16);
   nameBuffer[7] = (byte)(name2 >> 24);
   var newSection = new PESection(Encoding.ASCII.GetString(nameBuffer), 0xE0000040);
   writer.Sections.Insert(0, newSection); // insert first to ensure proper RVA

   uint alignment;

   alignment = writer.TextSection.Remove(writer.MetaData).Value;
   writer.TextSection.Add(writer.MetaData, alignment);

   alignment = writer.TextSection.Remove(writer.NetResources).Value;
   writer.TextSection.Add(writer.NetResources, alignment);

   alignment = writer.TextSection.Remove(writer.Constants).Value;
   newSection.Add(writer.Constants, alignment);

   // move some PE parts to separate section to prevent it from being hashed
   var peSection = new PESection("", 0x60000020);
   bool moved = false;
   if (writer.StrongNameSignature != null)
   {
    alignment = writer.TextSection.Remove(writer.StrongNameSignature).Value;
    peSection.Add(writer.StrongNameSignature, alignment);
    moved = true;
   }
   if (writer is ModuleWriter managedWriter)
   {
    if (managedWriter.ImportAddressTable != null)
    {
     alignment = writer.TextSection.Remove(managedWriter.ImportAddressTable).Value;
     peSection.Add(managedWriter.ImportAddressTable, alignment);
     moved = true;
    }
    if (managedWriter.StartupStub != null)
    {
     alignment = writer.TextSection.Remove(managedWriter.StartupStub).Value;
     peSection.Add(managedWriter.StartupStub, alignment);
     moved = true;
    }
   }
   if (moved)
    writer.Sections.Add(peSection);

   // move encrypted methods
   var encryptedChunk = new MethodBodyChunks(writer.TheOptions.ShareMethodBodies);
   newSection.Add(encryptedChunk, 4);
   foreach (MethodDef method in methods)
   {
    if (!method.HasBody)
     continue;
    dnlib.DotNet.Writer.MethodBody body = writer.MetaData.GetMethodBody(method);
    bool ok = writer.MethodBodies.Remove(body);

    encryptedChunk.Add(body);
   }

   // padding to prevent bad size due to shift division
   newSection.Add(new ByteArrayChunk(new byte[4]), 4);
  }

  void EncryptSection(ModuleWriterBase writer)
  {
   Stream stream = writer.DestinationStream;
   var reader = new BinaryReader(writer.DestinationStream);
   stream.Position = 0x3C;
   stream.Position = reader.ReadUInt32();

   stream.Position += 6;
   ushort sections = reader.ReadUInt16();
   stream.Position += 0xc;
   ushort optSize = reader.ReadUInt16();
   stream.Position += 2 + optSize;

   //at section table now
   uint encLoc = 0, encSize = 0;
   int origSects = -1;
   if (writer is NativeModuleWriter && writer.Module is ModuleDefMD)
    origSects = ((ModuleDefMD)writer.Module).MetaData.PEImage.ImageSectionHeaders.Count;
   for (int i = 0; i < sections; i++)
   {
    uint nameHash;
    if (origSects > 0)
    {
     origSects--;
     stream.Write(new byte[8], 0, 8);
     nameHash = 0;
    }
    else
     nameHash = reader.ReadUInt32() * reader.ReadUInt32();
    stream.Position += 8;
    if (nameHash == name1 * name2)
    {
     encSize = reader.ReadUInt32();
     encLoc = reader.ReadUInt32();
    }
    else if (nameHash != 0)
    {
     uint sectSize = reader.ReadUInt32();
     uint sectLoc = reader.ReadUInt32();
     Hash(stream, reader, sectLoc, sectSize);
    }
    else
     stream.Position += 8;
    stream.Position += 16;
   }

   uint[] key = DeriveKey();
   encSize >>= 2;
   stream.Position = encLoc;
   var result = new uint[encSize];
   for (uint i = 0; i < encSize; i++)
   {
    uint data = reader.ReadUInt32();
    result[i] = data ^ key[i & 0xf];
    key[i & 0xf] = (key[i & 0xf] ^ data) + 0x3dbb2819;
   }
   var byteResult = new byte[encSize << 2];
   Buffer.BlockCopy(result, 0, byteResult, 0, byteResult.Length);
   stream.Position = encLoc;
   stream.Write(byteResult, 0, byteResult.Length);
  }

  void Hash(Stream stream, BinaryReader reader, uint offset, uint size)
  {
   long original = stream.Position;
   stream.Position = offset;
   size >>= 2;
   for (uint i = 0; i < size; i++)
   {
    uint data = reader.ReadUInt32();
    uint tmp = (mut1 ^ data) + mut2 + mut3 * mut4;
    mut1 = mut2;
    mut2 = mut3;
    mut2 = mut4;
    mut4 = tmp;
   }
   stream.Position = original;
  }

  uint[] DeriveKey()
  {
   uint[] dst = new uint[0x10], src = new uint[0x10];
   for (int i = 0; i < 0x10; i++)
   {
    dst[i] = mut4;
    src[i] = mut2;
    mut1 = (mut2 >> 5) | (mut2 << 27);
    mut2 = (mut3 >> 3) | (mut3 << 29);
    mut3 = (mut4 >> 7) | (mut4 << 25);
    mut4 = (mut1 >> 11) | (mut1 << 21);
   }
   return deriver.DeriveKey(dst, src);
  }
 }

 internal class JITMode : IModeHandler
 {

  AntiTamperContext context;

  private ModuleDef Module;

  public JITMode(AntiTamperContext ctx , ModuleDef mod)
  {
   this.context = ctx;
   this.Module = mod;
  }


  static readonly CilBody NopBody = new CilBody
  {
   Instructions = {
    Instruction.Create(OpCodes.Ldnull),
    Instruction.Create(OpCodes.Throw)
   }
  };

  uint c;
  MethodDef cctor;
  MethodDef cctorRepl;
  IKeyDeriver deriver;
  byte[] fieldLayout;

  MethodDef initMethod;
  uint key;
  //List<MethodDef> methods;
  uint name1, name2;
  RandomGenerator random;
  uint v;
  uint x;
  uint z;

  public void HandleInject()
  {
   random = new RandomGenerator(Generator.GetBytes(32));
   z = random.NextUInt32();
   x = random.NextUInt32();
   c = random.NextUInt32();
   v = random.NextUInt32();
   name1 = random.NextUInt32() & 0x7f7f7f7f;
   name2 = random.NextUInt32() & 0x7f7f7f7f;
   key = random.NextUInt32();

   fieldLayout = new byte[6];
   for (int i = 0; i < 6; i++)
   {
    int index = random.NextInt32(0, 6);
    while (fieldLayout[index] != 0)
     index = random.NextInt32(0, 6);
    fieldLayout[index] = (byte)i;
   }



   deriver = new DynamicDeriver();
   deriver.Init(random);

   TypeDef initType = DnLibHelper.GetRuntimeType("Runtime.AntiTamperJIT");
   IEnumerable<IDnlibDef> defs = InjectHelper.Inject(initType, Module.GlobalType, Module);
   initMethod = defs.OfType<MethodDef>().Single(method => method.Name == "Initialize");

   initMethod.Body.SimplifyMacros(initMethod.Parameters);
   List<Instruction> instrs = initMethod.Body.Instructions.ToList();
   for (int i = 0; i < instrs.Count; i++)
   {
    Instruction instr = instrs[i];
    if (instr.OpCode == OpCodes.Ldtoken)
    {
     instr.Operand = Module.GlobalType;
    }
    else if (instr.OpCode == OpCodes.Call)
    {
     var method = (IMethod)instr.Operand;
     if (method.DeclaringType.Name == "Mutation" &&
         method.Name == "Crypt")
     {
      Instruction ldDst = instrs[i - 2];
      Instruction ldSrc = instrs[i - 1];
      Debug.Assert(ldDst.OpCode == OpCodes.Ldloc && ldSrc.OpCode == OpCodes.Ldloc);
      instrs.RemoveAt(i);
      instrs.RemoveAt(i - 1);
      instrs.RemoveAt(i - 2);
      instrs.InsertRange(i - 2, deriver.EmitDerivation(initMethod, (Local)ldDst.Operand, (Local)ldSrc.Operand));
     }
    }
   }
   initMethod.Body.Instructions.Clear();
   foreach (Instruction instr in instrs)
    initMethod.Body.Instructions.Add(instr);

   MutationHelper.InjectKeys(initMethod,
                             new[] { 0, 1, 2, 3, 4 },
                             new[] { (int)(name1 * name2), (int)z, (int)x, (int)c, (int)v });


   cctor = Module.GlobalType.FindStaticConstructor();

   cctorRepl = new MethodDefUser(Generator.GenerateString(), MethodSig.CreateStatic(Module.CorLibTypes.Void));
   cctorRepl.IsStatic = true;
   cctorRepl.Access = MethodAttributes.CompilerControlled;
   cctorRepl.Body = new CilBody();
   cctorRepl.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
   Module.GlobalType.Methods.Add(cctorRepl);

   MutationHelper.InjectKeys(defs.OfType<MethodDef>().Single(method => method.Name == "HookHandler"),
                             new[] { 0 }, new[] { (int)key });
   foreach (IDnlibDef def in defs)
   {
    if (def.Name == "MethodData")
    {
     var dataType = (TypeDef)def;
     FieldDef[] fields = dataType.Fields.ToArray();
     var layout = fieldLayout.Clone() as byte[];
     Array.Sort(layout, fields);
     for (byte j = 0; j < 6; j++)
      layout[j] = j;
     Array.Sort(fieldLayout, layout);
     fieldLayout = layout;
     dataType.Fields.Clear();
     foreach (FieldDef f in fields)
      dataType.Fields.Add(f);
    }
   }
  }

  public void HandleMD()
  {
   // move initialization away from module initializer
   cctorRepl.Body = cctor.Body;
   cctor.Body = new CilBody();
   cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, initMethod));
   cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, cctorRepl));
   cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

   context.CurrentModuleWriterListener.OnWriterEvent += OnWriterEvent;
  }

  void OnWriterEvent(object sender, ModuleWriterListenerEventArgs e)
  {
   var writer = (ModuleWriterBase)sender;
   if (e.WriterEvent == ModuleWriterEvent.MDBeginWriteMethodBodies)
   {
    CreateSection(writer);
   }
   else if (e.WriterEvent == ModuleWriterEvent.BeginStrongNameSign)
   {
    EncryptSection(writer);
   }
  }

  private void CreateSection(ModuleWriterBase writer)
  {
   // move some PE parts to separate section to prevent it from being hashed
   var peSection = new PESection("", 0x60000020);
   var moved = false;
   uint alignment;
   if (writer.StrongNameSignature != null)
   {
    alignment = writer.TextSection.Remove(writer.StrongNameSignature).Value;
    peSection.Add(writer.StrongNameSignature, alignment);
    moved = true;
   }
   var managedWriter = writer as ModuleWriter;
   if (managedWriter != null)
   {
    if (managedWriter.ImportAddressTable != null)
    {
     alignment = writer.TextSection.Remove(managedWriter.ImportAddressTable).Value;
     peSection.Add(managedWriter.ImportAddressTable, alignment);
     moved = true;
    }
    if (managedWriter.StartupStub != null)
    {
     alignment = writer.TextSection.Remove(managedWriter.StartupStub).Value;
     peSection.Add(managedWriter.StartupStub, alignment);
     moved = true;
    }
   }
   if (moved)
    writer.Sections.Add(peSection);

   // create section
   var nameBuffer = new byte[8];
   nameBuffer[0] = (byte)(name1 >> 0);
   nameBuffer[1] = (byte)(name1 >> 8);
   nameBuffer[2] = (byte)(name1 >> 16);
   nameBuffer[3] = (byte)(name1 >> 24);
   nameBuffer[4] = (byte)(name2 >> 0);
   nameBuffer[5] = (byte)(name2 >> 8);
   nameBuffer[6] = (byte)(name2 >> 16);
   nameBuffer[7] = (byte)(name2 >> 24);
   var newSection = new PESection(Encoding.ASCII.GetString(nameBuffer), 0xE0000040);
   writer.Sections.Insert(random.NextInt32(writer.Sections.Count), newSection);

   // random padding at beginning to prevent revealing hash key
   newSection.Add(new ByteArrayChunk(random.NextBytes(0x10)), 0x10);

   // create index
   var bodyIndex = new JITBodyIndex(context.Targets.Select(method => writer.MetaData.GetToken(method).Raw));
   newSection.Add(bodyIndex, 0x10);

   // save methods
   foreach (var method in context.Targets)
   {
    if (!method.HasBody)
     continue;

    var token = writer.MetaData.GetToken(method);

    var jitBody = new JITMethodBody();
    var bodyWriter = new JITMethodBodyWriter(writer.MetaData, method.Body, jitBody, random.NextUInt32(), writer.MetaData.KeepOldMaxStack || method.Body.KeepOldMaxStack);
    bodyWriter.Write();
    jitBody.Serialize(token.Raw, key, fieldLayout);
    bodyIndex.Add(token.Raw, jitBody);

    method.Body = NopBody;
    writer.MetaData.TablesHeap.MethodTable[token.Rid].ImplFlags |= (ushort)MethodImplAttributes.NoInlining;
   }
   bodyIndex.PopulateSection(newSection);

   // padding to prevent bad size due to shift division
   newSection.Add(new ByteArrayChunk(new byte[4]), 4);
  }

  private void EncryptSection(ModuleWriterBase writer)
  {
   var stream = writer.DestinationStream;
   var reader = new BinaryReader(writer.DestinationStream);
   stream.Position = 0x3C;
   stream.Position = reader.ReadUInt32();

   stream.Position += 6;
   var sections = reader.ReadUInt16();
   stream.Position += 0xc;
   var optSize = reader.ReadUInt16();
   stream.Position += 2 + optSize;

   uint encLoc = 0, encSize = 0;
   var origSects = -1;
   if (writer is NativeModuleWriter && writer.Module is ModuleDefMD)
    origSects = ((ModuleDefMD)writer.Module).MetaData.PEImage.ImageSectionHeaders.Count;
   for (var i = 0; i < sections; i++)
   {
    uint nameHash;
    if (origSects > 0)
    {
     origSects--;
     stream.Write(new byte[8], 0, 8);
     nameHash = 0;
    }
    else
    {
     nameHash = reader.ReadUInt32() * reader.ReadUInt32();
    }
    stream.Position += 8;
    if (nameHash == name1 * name2)
    {
     encSize = reader.ReadUInt32();
     encLoc = reader.ReadUInt32();
    }
    else if (nameHash != 0)
    {
     var sectSize = reader.ReadUInt32();
     var sectLoc = reader.ReadUInt32();
     Hash(stream, reader, sectLoc, sectSize);
    }
    else
    {
     stream.Position += 8;
    }
    stream.Position += 16;
   }

   var key = DeriveKey();
   encSize >>= 2;
   stream.Position = encLoc;
   var result = new uint[encSize];
   for (uint i = 0; i < encSize; i++)
   {
    var data = reader.ReadUInt32();
    result[i] = data ^ key[i & 0xf];
    key[i & 0xf] = (key[i & 0xf] ^ data) + 0x3dbb2819;
   }
   var byteResult = new byte[encSize << 2];
   Buffer.BlockCopy(result, 0, byteResult, 0, byteResult.Length);
   stream.Position = encLoc;
   stream.Write(byteResult, 0, byteResult.Length);
  }

  private void Hash(Stream stream, BinaryReader reader, uint offset, uint size)
  {
   var original = stream.Position;
   stream.Position = offset;
   size >>= 2;
   for (uint i = 0; i < size; i++)
   {
    var data = reader.ReadUInt32();
    var tmp = (z ^ data) + x + c * v;
    z = x;
    x = c;
    x = v;
    v = tmp;
   }
   stream.Position = original;
  }

  private uint[] DeriveKey()
  {
   uint[] dst = new uint[0x10], src = new uint[0x10];
   for (var i = 0; i < 0x10; i++)
   {
    dst[i] = v;
    src[i] = x;
    z = (x >> 5) | (x << 27);
    x = (c >> 3) | (c << 29);
    c = (v >> 7) | (v << 25);
    v = (z >> 11) | (z << 21);
   }
   return deriver.DeriveKey(dst, src);
  }
 }


 internal class DynamicDeriver : IKeyDeriver
 {
  StatementBlock derivation;
  Action<uint[], uint[]> encryptFunc;

  public void Init(RandomGenerator random)
  {
   StatementBlock dummy;
   new DynCipherService().GenerateCipherPair(random, out derivation, out dummy);
   var dmCodeGen = new DMCodeGen(typeof(void), new[] {
    Tuple.Create("{BUFFER}", typeof(uint[])),
    Tuple.Create("{KEY}", typeof(uint[]))
   });
   dmCodeGen.GenerateCIL(derivation);
   encryptFunc = dmCodeGen.Compile<Action<uint[], uint[]>>();
  }

  public uint[] DeriveKey(uint[] a, uint[] b)
  {
   var ret = new uint[0x10];
   Buffer.BlockCopy(a, 0, ret, 0, a.Length * sizeof(uint));
   encryptFunc(ret, b);
   return ret;
  }

  public IEnumerable<Instruction> EmitDerivation(MethodDef method, Local dst, Local src)
  {
   var ret = new List<Instruction>();
   var codeGen = new CodeGen(dst, src, method, ret);
   codeGen.GenerateCIL(derivation);
   codeGen.Commit(method.Body);
   return ret;
  }

  class CodeGen : CILCodeGen
  {
   readonly Local block;
   readonly Local key;

   public CodeGen(Local block, Local key, MethodDef method, IList<Instruction> instrs)
    : base(method, instrs)
   {
    this.block = block;
    this.key = key;
   }

   protected override Local Var(Variable var)
   {
    if (var.Name == "{BUFFER}")
     return block;
    if (var.Name == "{KEY}")
     return key;
    return base.Var(var);
   }
  }
 }

 internal class NormalDeriver : IKeyDeriver
 {
  public void Init(RandomGenerator random)
  {
   //
  }

  public uint[] DeriveKey(uint[] a, uint[] b)
  {
   var ret = new uint[0x10];
   for (int i = 0; i < 0x10; i++)
   {
    switch (i % 3)
    {
     case 0:
      ret[i] = a[i] ^ b[i];
      break;
     case 1:
      ret[i] = a[i] * b[i];
      break;
     case 2:
      ret[i] = a[i] + b[i];
      break;
    }
   }
   return ret;
  }

  public IEnumerable<Instruction> EmitDerivation(MethodDef method, Local dst, Local src)
  {
   for (int i = 0; i < 0x10; i++)
   {
    yield return Instruction.Create(OpCodes.Ldloc, dst);
    yield return Instruction.Create(OpCodes.Ldc_I4, i);
    yield return Instruction.Create(OpCodes.Ldloc, dst);
    yield return Instruction.Create(OpCodes.Ldc_I4, i);
    yield return Instruction.Create(OpCodes.Ldelem_U4);
    yield return Instruction.Create(OpCodes.Ldloc, src);
    yield return Instruction.Create(OpCodes.Ldc_I4, i);
    yield return Instruction.Create(OpCodes.Ldelem_U4);
    switch (i % 3)
    {
     case 0:
      yield return Instruction.Create(OpCodes.Xor);
      break;
     case 1:
      yield return Instruction.Create(OpCodes.Mul);
      break;
     case 2:
      yield return Instruction.Create(OpCodes.Add);
      break;
    }
    yield return Instruction.Create(OpCodes.Stelem_I4);
   }
  }
 }

 internal struct JITEHClause
 {
  public uint ClassTokenOrFilterOffset;
  public uint Flags;
  public uint HandlerLength;
  public uint HandlerOffset;
  public uint TryLength;
  public uint TryOffset;
 }

 internal class JITMethodBody : IChunk
 {
  public byte[] Body;
  public JITEHClause[] EHs;
  public byte[] ILCode;
  public byte[] LocalVars;
  public uint MaxStack;
  public uint MulSeed;

  public uint Offset;
  public uint Options;

  public FileOffset FileOffset
  {
   get;
   set;
  }

  public RVA RVA
  {
   get;
   set;
  }

  public void SetOffset(FileOffset offset, RVA rva)
  {
   FileOffset = offset;
   RVA = rva;
  }

  public uint GetFileLength()
  {
   return (uint)Body.Length + 4;
  }

  public uint GetVirtualSize()
  {
   return GetFileLength();
  }

  public void WriteTo(BinaryWriter writer)
  {
   writer.Write((uint)(Body.Length >> 2));
   writer.Write(Body);
  }

  public void Serialize(uint token, uint key, byte[] fieldLayout)
  {
   using (var ms = new MemoryStream())
   {
    var writer = new BinaryWriter(ms);
    foreach (var i in fieldLayout)
     switch (i)
     {
      case 0:
       writer.Write((uint)ILCode.Length);
       break;
      case 1:
       writer.Write(MaxStack);
       break;
      case 2:
       writer.Write((uint)EHs.Length);
       break;
      case 3:
       writer.Write((uint)LocalVars.Length);
       break;
      case 4:
       writer.Write(Options);
       break;
      case 5:
       writer.Write(MulSeed);
       break;
     }

    writer.Write(ILCode);
    writer.Write(LocalVars);
    foreach (var clause in EHs)
    {
     writer.Write(clause.Flags);
     writer.Write(clause.TryOffset);
     writer.Write(clause.TryLength);
     writer.Write(clause.HandlerOffset);
     writer.Write(clause.HandlerLength);
     writer.Write(clause.ClassTokenOrFilterOffset);
    }
    writer.WriteZeros(4 - ((int)ms.Length & 3)); // pad to 4 bytes
    Body = ms.ToArray();
   }
   Debug.Assert(Body.Length % 4 == 0);
   // encrypt body
   var state = token * key;
   var counter = state;
   for (uint i = 0; i < Body.Length; i += 4)
   {
    var data = Body[i] | (uint)(Body[i + 1] << 8) | (uint)(Body[i + 2] << 16) | (uint)(Body[i + 3] << 24);
    Body[i + 0] ^= (byte)(state >> 0);
    Body[i + 1] ^= (byte)(state >> 8);
    Body[i + 2] ^= (byte)(state >> 16);
    Body[i + 3] ^= (byte)(state >> 24);
    state += data ^ counter;
    counter ^= (state >> 5) | (state << 27);
   }
  }
 }

 internal class JITMethodBodyWriter : MethodBodyWriterBase
 {
  private readonly CilBody body;
  private readonly JITMethodBody jitBody;
  private readonly bool keepMaxStack;
  private readonly MetaData metadata;

  public JITMethodBodyWriter(MetaData md, CilBody body, JITMethodBody jitBody, uint mulSeed, bool keepMaxStack) :
      base(body.Instructions, body.ExceptionHandlers)
  {
   metadata = md;
   this.body = body;
   this.jitBody = jitBody;
   this.keepMaxStack = keepMaxStack;
   this.jitBody.MulSeed = mulSeed;
  }

  public void Write()
  {
   var codeSize = InitializeInstructionOffsets();
   jitBody.MaxStack = keepMaxStack ? body.MaxStack : GetMaxStack();

   jitBody.Options = 0;
   if (body.InitLocals)
    jitBody.Options |= 0x10;

   if (body.Variables.Count > 0)
   {
    var local = new LocalSig(body.Variables.Select(var => var.Type).ToList());
    jitBody.LocalVars = SignatureWriter.Write(metadata, local);
   }
   else
   {
    jitBody.LocalVars = new byte[0];
   }

   using (var ms = new MemoryStream())
   {
    var _codeSize = WriteInstructions(new BinaryWriter(ms));
    Debug.Assert(codeSize == _codeSize);
    jitBody.ILCode = ms.ToArray();
   }

   jitBody.EHs = new JITEHClause[exceptionHandlers.Count];
   if (exceptionHandlers.Count > 0)
   {
    jitBody.Options |= 8;
    for (var i = 0; i < exceptionHandlers.Count; i++)
    {
     var eh = exceptionHandlers[i];
     jitBody.EHs[i].Flags = (uint)eh.HandlerType;

     var tryStart = GetOffset(eh.TryStart);
     var tryEnd = GetOffset(eh.TryEnd);
     jitBody.EHs[i].TryOffset = tryStart;
     jitBody.EHs[i].TryLength = tryEnd - tryStart;

     var handlerStart = GetOffset(eh.HandlerStart);
     var handlerEnd = GetOffset(eh.HandlerEnd);
     jitBody.EHs[i].HandlerOffset = handlerStart;
     jitBody.EHs[i].HandlerLength = handlerEnd - handlerStart;

     if (eh.HandlerType == ExceptionHandlerType.Catch)
     {
      var token = metadata.GetToken(eh.CatchType).Raw;
      if ((token & 0xff000000) == 0x1b000000)
       jitBody.Options |= 0x80;

      jitBody.EHs[i].ClassTokenOrFilterOffset = token;
     }
     else if (eh.HandlerType == ExceptionHandlerType.Filter)
     {
      jitBody.EHs[i].ClassTokenOrFilterOffset = GetOffset(eh.FilterStart);
     }
    }
   }
  }

  protected override void WriteInlineField(BinaryWriter writer, Instruction instr)
  {
   writer.Write(metadata.GetToken(instr.Operand).Raw);
  }

  protected override void WriteInlineMethod(BinaryWriter writer, Instruction instr)
  {
   writer.Write(metadata.GetToken(instr.Operand).Raw);
  }

  protected override void WriteInlineSig(BinaryWriter writer, Instruction instr)
  {
   writer.Write(metadata.GetToken(instr.Operand).Raw);
  }

  protected override void WriteInlineString(BinaryWriter writer, Instruction instr)
  {
   writer.Write(metadata.GetToken(instr.Operand).Raw);
  }

  protected override void WriteInlineTok(BinaryWriter writer, Instruction instr)
  {
   writer.Write(metadata.GetToken(instr.Operand).Raw);
  }

  protected override void WriteInlineType(BinaryWriter writer, Instruction instr)
  {
   writer.Write(metadata.GetToken(instr.Operand).Raw);
  }
 }

 internal class JITBodyIndex : IChunk
 {
  private readonly Dictionary<uint, JITMethodBody> bodies;

  public JITBodyIndex(IEnumerable<uint> tokens)
  {
   bodies = tokens.ToDictionary(token => token, token => (JITMethodBody)null);
  }

  public FileOffset FileOffset
  {
   get;
   set;
  }

  public RVA RVA
  {
   get;
   set;
  }

  public void SetOffset(FileOffset offset, RVA rva)
  {
   FileOffset = offset;
   RVA = rva;
  }

  public uint GetFileLength()
  {
   return (uint)bodies.Count * 8 + 4;
  }

  public uint GetVirtualSize()
  {
   return GetFileLength();
  }

  public void WriteTo(BinaryWriter writer)
  {
   var length = GetFileLength() - 4; // minus length field
   writer.Write((uint)bodies.Count);
   foreach (var entry in bodies.OrderBy(entry => entry.Key))
   {
    writer.Write(entry.Key);
    Debug.Assert(entry.Value != null);
    Debug.Assert((length + entry.Value.Offset) % 4 == 0);
    writer.Write((length + entry.Value.Offset) >> 2);
   }
  }

  public void Add(uint token, JITMethodBody body)
  {
   Debug.Assert(bodies.ContainsKey(token));
   bodies[token] = body;
  }

  public void PopulateSection(PESection section)
  {
   uint offset = 0;
   foreach (var entry in bodies.OrderBy(entry => entry.Key))
   {
    Debug.Assert(entry.Value != null);
    section.Add(entry.Value, 4);
    entry.Value.Offset = offset;

    Debug.Assert(entry.Value.GetFileLength() % 4 == 0);
    offset += entry.Value.GetFileLength();
   }
  }
 }

 public class ModuleWriterListener : IModuleWriterListener
 {
  void IModuleWriterListener.OnWriterEvent(ModuleWriterBase writer, ModuleWriterEvent evt)
  {
   if (evt == ModuleWriterEvent.PESectionsCreated)
    NativeEraser.Erase(writer as NativeModuleWriter, writer.Module as ModuleDefMD);
   if (OnWriterEvent != null)
   {
    OnWriterEvent(writer, new ModuleWriterListenerEventArgs(evt));
   }
  }
  public event EventHandler<ModuleWriterListenerEventArgs> OnWriterEvent;
 }
 public class ModuleWriterListenerEventArgs : EventArgs
 {
  public ModuleWriterListenerEventArgs(ModuleWriterEvent evt)
  {
   WriterEvent = evt;
  }

  public ModuleWriterEvent WriterEvent { get; private set; }
 }
 internal class NativeEraser
 {
  static void Erase(Tuple<uint, uint, byte[]> section, uint offset, uint len)
  {
   Array.Clear(section.Item3, (int)(offset - section.Item1), (int)len);
  }

  static void Erase(List<Tuple<uint, uint, byte[]>> sections, uint beginOffset, uint size)
  {
   foreach (var sect in sections)
    if (beginOffset >= sect.Item1 && beginOffset + size < sect.Item2)
    {
     Erase(sect, beginOffset, size);
     break;
    }
  }

  static void Erase(List<Tuple<uint, uint, byte[]>> sections, IFileSection s)
  {
   foreach (var sect in sections)
    if ((uint)s.StartOffset >= sect.Item1 && (uint)s.EndOffset < sect.Item2)
    {
     Erase(sect, (uint)s.StartOffset, (uint)(s.EndOffset - s.StartOffset));
     break;
    }
  }

  static void Erase(List<Tuple<uint, uint, byte[]>> sections, uint methodOffset)
  {
   foreach (var sect in sections)
    if (methodOffset >= sect.Item1 && methodOffset - sect.Item1 < sect.Item3.Length)
    {
     uint f = sect.Item3[methodOffset - sect.Item1];
     uint size;
     switch ((f & 7))
     {
      case 2:
      case 6:
       size = (f >> 2) + 1;
       break;

      case 3:
       f |= (uint)((sect.Item3[methodOffset - sect.Item1 + 1]) << 8);
       size = (f >> 12) * 4;
       uint codeSize = BitConverter.ToUInt32(sect.Item3, (int)(methodOffset - sect.Item1 + 4));
       size += codeSize;
       break;
      default:
       return;
     }
     Erase(sect, methodOffset, size);
    }
  }

  public static void Erase(NativeModuleWriter writer, ModuleDefMD module)
  {
   if (writer == null || module == null)
    return;

   var sections = new List<Tuple<uint, uint, byte[]>>();
   var s = new MemoryStream();
   foreach (var origSect in writer.OrigSections)
   {
    var oldChunk = origSect.Chunk;
    var sectHdr = origSect.PESection;

    s.SetLength(0);
    oldChunk.WriteTo(new BinaryWriter(s));
    var buf = s.ToArray();
    var newChunk = new BinaryReaderChunk(MemoryImageStream.Create(buf), oldChunk.GetVirtualSize());
    newChunk.SetOffset(oldChunk.FileOffset, oldChunk.RVA);

    origSect.Chunk = newChunk;

    sections.Add(Tuple.Create(
        sectHdr.PointerToRawData,
        sectHdr.PointerToRawData + sectHdr.SizeOfRawData,
        buf));
   }

   var md = module.MetaData;

   var row = md.TablesStream.MethodTable.Rows;
   for (uint i = 1; i <= row; i++)
   {
    var method = md.TablesStream.ReadMethodRow(i);
    var codeType = ((dnlib.DotNet.MethodImplAttributes)method.ImplFlags & dnlib.DotNet.MethodImplAttributes.CodeTypeMask);
    if (codeType == dnlib.DotNet.MethodImplAttributes.IL)
     Erase(sections, (uint)md.PEImage.ToFileOffset((RVA)method.RVA));
   }

   var res = md.ImageCor20Header.Resources;
   if (res.Size > 0)
    Erase(sections, (uint)res.StartOffset, res.Size);

   Erase(sections, md.ImageCor20Header);
   Erase(sections, md.MetaDataHeader);
   foreach (var stream in md.AllStreams)
    Erase(sections, stream);
  }
 }

}
