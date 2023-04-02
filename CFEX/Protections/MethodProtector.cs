using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Reflection;
using System.IO;
using Protector.Utils;
using dnlib.DotNet.Writer;

using Protector.IlDyn;
using dnlib.IO;
using dnlib.PE;
using System.Security.Cryptography;

namespace Protector
{

 //its jit hook basicaly
 class MethodProtectorEngine
 {
  IMethodProtector protector;
  public MethodProtectorEngine()
  {
   protector = new MethodProtector();
  }

  public byte[] Protect(byte[] inputModule)
  {
   protector.Initialize(inputModule);
   protector.SearchTargets();
   protector.AddSignature();
   protector.GetReflectionMethods();
   protector.InjectPhase();
   protector.ProtectMethods();
   return protector.GetResult();
  }
 }

 public interface IMethodProtector
 {
  void Initialize(byte[] inputModule);
  void SearchTargets();
  void AddSignature();
  void GetReflectionMethods();
  void InjectPhase();
  void ProtectMethods();
  byte[] GetResult();
 }

 class MethodProtector : IMethodProtector
 {
  public List<MethodDef> MethodsDnlib = new List<MethodDef>();
  private List<byte[]> MethodsRefl = new List<byte[]>();
  private List<uint> Tokens = new List<uint>();
  private ModuleDef Module;
  private byte[] ReflectionModule;
  private TypeDef RuntimeType;
  private ModuleDef DynamicDllLoader;
  private byte[] DynamicDllLoaderBytes;
  private StringHiderProtection StringHider;
  private EddyCZFileFormat EddyCZFormat;

  public void Initialize(byte[] inputModule)
  {
   Module = ModuleDefMD.Load(inputModule);

   EddyCZFormat = new EddyCZFileFormat();

   //AddInitilizer();


   


  }

  private void AddInitilizer()
  {
   MethodDef cctor = Module.GlobalType.FindOrCreateStaticConstructor();

   TypeDefUser NewType = new TypeDefUser("JIT", "JITNamespace",
Module.CorLibTypes.Object.TypeDefOrRef);
   NewType.Attributes = dnlib.DotNet.TypeAttributes.NotPublic |
    dnlib.DotNet.TypeAttributes.AutoLayout |
        dnlib.DotNet.TypeAttributes.Class |
        dnlib.DotNet.TypeAttributes.AnsiClass;
   Module.Types.Add(NewType);

   RuntimeType = NewType;


   var rtType = DnLibHelper.GetRuntimeType("Runtime.JITRuntime");
   IEnumerable<IDnlibDef> defs = InjectHelper.Inject(rtType, NewType, Module);
   MethodDef initializer = defs.OfType<MethodDef>().Single(method => method.Name == "Hook");

   MethodDef antiDump = defs.OfType<MethodDef>().Single(method => method.Name == "AntiDump");

   cctor.Body.Instructions.Clear();
   cctor.Body.Instructions.Add(new Instruction(OpCodes.Call, initializer));
   cctor.Body.Instructions.Add(new Instruction(OpCodes.Ret));
  }

  private void AddDynamicInitializer()
  {
   string dllbytes = Convert.ToBase64String(File.ReadAllBytes("JITHook.dll")); //The native c++ library
   var ctor = Module.GlobalType.FindOrCreateStaticConstructor();
   MethodDef invoke = null;
   foreach (TypeDef t in DynamicDllLoader.Types)
   {
    var m = t.FindMethod("Invoke__");
    if (m != null) invoke = m;
   }

   int position = ctor.Body.Instructions.Count - 2;

   dnlib.DotNet.MethodImplAttributes methImplFlags = dnlib.DotNet.MethodImplAttributes.IL | dnlib.DotNet.MethodImplAttributes.Managed;
   dnlib.DotNet.MethodAttributes methFlags = dnlib.DotNet.MethodAttributes.Private | dnlib.DotNet.MethodAttributes.Static | dnlib.DotNet.MethodAttributes.ReuseSlot;
   MethodDef meth1 = new MethodDefUser(Generator.GenerateString(),
                       MethodSig.CreateStatic(Module.CorLibTypes.Void),
                       methImplFlags, methFlags);
   Module.GlobalType.Methods.Add(meth1);

   CilBody body = new CilBody();
   meth1.Body = body;

   body.Instructions.Add(OpCodes.Ldstr.ToInstruction(dllbytes));
   body.Instructions.Add(OpCodes.Call.ToInstruction(ctor.Module.Import(invoke)));
   body.Instructions.Add(OpCodes.Ret.ToInstruction());

   ctor.Body.Instructions.Insert(position, OpCodes.Call.ToInstruction(ctor.Module.Import(meth1)));
   StringHider.ProtectMethod(meth1);
  }

  private void EmbedLoader()
  {

   var mod = Module;
   dnlib.DotNet.MethodImplAttributes methImplFlags = dnlib.DotNet.MethodImplAttributes.IL | dnlib.DotNet.MethodImplAttributes.Managed;
   dnlib.DotNet.MethodAttributes methFlags = dnlib.DotNet.MethodAttributes.Private | dnlib.DotNet.MethodAttributes.Static | dnlib.DotNet.MethodAttributes.ReuseSlot;
   MethodDef meth1 = new MethodDefUser("Init_",
               MethodSig.CreateStatic(mod.Import(typeof(Assembly)).ToTypeSig(), mod.CorLibTypes.Object, mod.Import(typeof(ResolveEventArgs)).ToTypeSig()),
               methImplFlags, methFlags);
   mod.GlobalType.Methods.Add(meth1);
   //mod.EntryPoint.DeclaringType.Methods.Add(meth1);

   CilBody body = new CilBody();
   meth1.Body = body;
   // Name the 1st and 2nd args a and b, respectively
   meth1.ParamDefs.Add(new ParamDefUser("a", 1));
   meth1.ParamDefs.Add(new ParamDefUser("b", 2));
   body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction());
   body.Instructions.Add(OpCodes.Callvirt.ToInstruction(mod.Import(typeof(ResolveEventArgs).GetProperty("Name").GetGetMethod())));
   body.Instructions.Add(OpCodes.Ldstr.ToInstruction("JITDynamic"));
   body.Instructions.Add(OpCodes.Callvirt.ToInstruction(mod.Import(typeof(String).GetMethod("StartsWith", new Type[] { typeof(string) }))));
   Instruction ldnull = OpCodes.Ldnull.ToInstruction();
   body.Instructions.Add(OpCodes.Brfalse_S.ToInstruction(ldnull));
   body.Instructions.Add(OpCodes.Ldstr.ToInstruction(Convert.ToBase64String(DynamicDllLoaderBytes)));
   body.Instructions.Add(OpCodes.Call.ToInstruction(mod.Import(typeof(Convert).GetMethod("FromBase64String"))));
   body.Instructions.Add(OpCodes.Call.ToInstruction(mod.Import(typeof(Assembly).GetMethod("Load", new Type[] { typeof(byte[]) }))));
   body.Instructions.Add(OpCodes.Ret.ToInstruction());
   body.Instructions.Add(ldnull);
   body.Instructions.Add(OpCodes.Ret.ToInstruction());


   var strangeconstructor = typeof(ResolveEventHandler).GetConstructor(new Type[] { typeof(object), typeof(IntPtr) });

   var body2 = mod.GlobalType.FindOrCreateStaticConstructor().Body;
   body2.Instructions.Insert(0, OpCodes.Callvirt.ToInstruction(mod.Import(typeof(AppDomain).GetEvent("AssemblyResolve").GetAddMethod())));
   body2.Instructions.Insert(0, OpCodes.Newobj.ToInstruction(mod.Import(strangeconstructor)));
   body2.Instructions.Insert(0, OpCodes.Ldftn.ToInstruction(meth1));
   body2.Instructions.Insert(0, OpCodes.Ldnull.ToInstruction());
   body2.Instructions.Insert(0, OpCodes.Call.ToInstruction(mod.Import(typeof(AppDomain).GetProperty("CurrentDomain").GetGetMethod())));
   meth1.Name = Generator.GenerateString();
   StringHider.ProtectMethod(meth1);
  }

  //There i search targets ...
  public void SearchTargets()
  {
   foreach (TypeDef t in Module.Types)
   {
    foreach (MethodDef m in t.Methods)
    {
     if (m.HasBody && !m.IsConstructor && m.DeclaringType != Module.GlobalType && m.DeclaringType != RuntimeType)
     {
      MethodsDnlib.Add(m);
      Tokens.Add(m.MDToken.ToUInt32());
     }
    }
   }
  }


  //There i add 5 NOP to method. Its signature for decision what method is encrypted
  public void AddSignature()
  {
   foreach (MethodDef m in MethodsDnlib)
   {
    List<byte> pattern = new List<byte>();
    for (int i = 0; i < 5; i++)
    {
     Instruction nop = Instruction.Create(OpCodes.Nop);
     m.Body.Instructions.Insert(0, nop);
     pattern.Add((byte)nop.OpCode.Code);
    }
   }
   ReflectionModule = UpdateModule();
  }

  //Get IL bodies
  public void GetReflectionMethods()
  {
   Assembly asm = Assembly.Load(ReflectionModule);

   foreach (var t in asm.GetTypes())
   {
    MethodInfo[] methods = t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Default | BindingFlags.Static);
    foreach (var m in methods)
    {
     foreach (var tokken in Tokens)
     {
      if (m.MetadataToken == tokken)
      {
       byte[] ILbyte = m.GetMethodBody().GetILAsByteArray();
       MethodsRefl.Add(m.GetMethodBody().GetILAsByteArray());
       EncryptDecrypt(ILbyte);
       EddyCZFormat.AddData((uint)m.MetadataToken, ILbyte);
      }
     }
    }
   }
  }

  public void InjectPhase()
  {
   Module = ModuleDefMD.Load(ReflectionModule);
   DynamicDllLoader = ModuleDefMD.Load("JITDynamic.dll");
   DynamicDllLoaderBytes = UpdateModuleWithListener(DynamicDllLoader);
   DynamicDllLoader = ModuleDefMD.Load(DynamicDllLoaderBytes);

   File.WriteAllBytes("Dyn.dll",DynamicDllLoaderBytes);

   StringHider = new StringHiderProtection(Module);

   AddDynamicInitializer();
   EmbedLoader();
   StringHider.Finish();
   new Renamer3().Rename(Module);

   ReflectionModule = UpdateModule();
   File.WriteAllBytes("test.exe", ReflectionModule);
  }

  //Encrypt methods
  public void ProtectMethods()
  {
   foreach (var method in MethodsRefl)
   {

    

    int pos = new BoyerMoore(method).Search(ReflectionModule, 0);

    string posHex = pos.ToString("x");
    ReplaceWithNOP(method);
    for (int i = 0; i < method.Length; i++)
    {
     ReflectionModule[pos] = method[i];
     pos++;
    }
   }
  }

  public byte[] GetResult()
  {
   return ReflectionModule;
  }

  private byte[] UpdateModule()
  {
   ModuleWriterOptions opts = new ModuleWriterOptions(Module);
   opts.MetaDataLogger = DummyLogger.NoThrowInstance;
   opts.MetaDataOptions.Flags = MetaDataFlags.PreserveAllMethodRids;
   MemoryStream stream = new MemoryStream();
   Module.Write(stream, opts);
   return stream.ToArray();
  }
  private string GetName(int id)
  {
   byte[] hash = SHA1.Create().ComputeHash(BitConverter.GetBytes(id));
   string result = null;
   foreach (var h in hash)
   {
    result += h.ToString("x2").ToUpper();
   }
   return result;
  }
  private byte[] UpdateModuleWithListener(ModuleDef mod)
  {

   string idStr = GetName(23);
   byte[] data = EddyCZFormat.CreateFile();
   string b64 = Convert.ToBase64String(data);
   mod.Resources.Add(new EmbeddedResource(idStr, data,
ManifestResourceAttributes.Private));

   ModuleWriterListener CurrentModuleWriterListener = new ModuleWriterListener();
   ModuleWriterOptions CurrentModuleWriterOptions = new ModuleWriterOptions(mod, CurrentModuleWriterListener);
   //CurrentModuleWriterListener.OnWriterEvent += AddMetadata;
   MemoryStream output = new MemoryStream();
   CurrentModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;
   //ctx.CurrentModuleWriterOptions.MetaDataOptions.Flags = MetaDataFlags.PreserveAllMethodRids;

   if (CurrentModuleWriterOptions is ModuleWriterOptions)
   {
    try
    {
     mod.Write(output, (ModuleWriterOptions)CurrentModuleWriterOptions);
    }
    catch (Exception e)
    {

    }

   }
   return output.ToArray();
  }

  private void AddMetadata(object sender, ModuleWriterListenerEventArgs e)
  {
   var writer = (ModuleWriterBase)sender;
   if (e.WriterEvent == ModuleWriterEvent.MDEndWriteMethodBodies)
   {
    
    //writer.TheOptions.MetaDataOptions.OtherHeapsEnd.Add(new RawHeap("Eddy^CZ", fileFormat));
   }
  }

  private void ReplaceWithNOP(byte[] data)
  {
   for (int i = 0; i < data.Length; i++)
   {
    data[i] = (byte)0x00;
   }
  }

  private void EncryptDecrypt(byte[] data)
  {
   byte[] key = Convert.FromBase64String("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==");

   for (int i = 0; i < data.Length; i++)
   {
    data[i] = (byte)(data[i] ^ key[i % key.Length]);
   }
  }
  class RawHeap : HeapBase
  {
   readonly byte[] content;
   readonly string name;

   public RawHeap(string name, byte[] content)
   {
    this.name = name;
    this.content = content;
   }

   public override string Name
   {
    get { return name; }
   }

   public override uint GetRawLength()
   {
    return (uint)content.Length;
   }

   protected override void WriteToImpl(BinaryWriter writer)
   {
    writer.Write(content);
   }
  }
 }


 }
