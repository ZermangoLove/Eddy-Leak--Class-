using dnlib.DotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Eddy_Protector_Core.Core;
using Eddy_Protector.Virtualization;
using System.Runtime.CompilerServices;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Protector.Helpers;
using System.IO;
using Protector.Handler;

namespace Protector.Protections.Virtualization
{
 class VM
 {

  public static readonly object VirtualizerKey = new object();
  public static readonly object MergeKey = new object();
  public static readonly object ExportKey = new object();

  public List<MethodDef> Targets =new List<MethodDef>();


  public byte[] Protect(byte[] input_module, ProtectorContext ctx)
  {

   ModuleDef mod = new ModuleHandler().ByteToModuleDef(input_module);

   ctx.CurrentModuleWriterListener = new ModuleWriterListener();
   ctx.CurrentModuleWriterOptions = new ModuleWriterOptions(mod, ctx.CurrentModuleWriterListener);

   Initialize(mod, ctx);

   return UpdateModule(mod, ctx);
  }

  public byte[] UpdateModule(ModuleDef module, ProtectorContext ctx)
  {
   MemoryStream output = new MemoryStream();
   ctx.CurrentModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;
   if (ctx.CurrentModuleWriterOptions is ModuleWriterOptions)
   {
    module.Write(output, (ModuleWriterOptions)ctx.CurrentModuleWriterOptions);
   }
   return output.ToArray();
  }


  public void AddTarget(MethodDef method)
  {
   Targets.Add(method);
  }

  public void Initialize(ModuleDef module, ProtectorContext context)
  {
   ModuleDef merge = null;

   string rtName = new Generators().GetSHA1FromString(Guid.NewGuid().ToString().ToUpper());
   ModuleDefMD RuntimeModule = ModuleDefMD.Load("Eddy_Protector_VM_RT.dll");
   RuntimeModule.Assembly.Name = rtName+".dll";
   RuntimeModule.Name = rtName + ".dll";

   var anno = new Annotations();
   var vr = new Virtualizer(context.random_generator.RandomInt(), false);

   vr.Initialize(RuntimeModule);

   anno.Set(context, VirtualizerKey, vr);
   anno.Set(context, MergeKey, merge);

   vr.CommitRuntime(module);



   var ctor = typeof(InternalsVisibleToAttribute).GetConstructor(new[] { typeof(string) });
   var methods = new HashSet<MethodDef>();


   #region No used

   //foreach (var type in module.GetTypes())
   //{
   // if (type.IsGlobalModuleType)
   // {
   //  foreach (var m in type.Methods)
   //  {
   //   if (m.IsConstructor)
   //   {
   //    methods.Add(m);
   //   }
   //  }
   // }
   //}

   //foreach (var type in module.GetTypes())
   //{
   // foreach (var m in type.Methods)
   // {
   //  if (m.HasBody)
   //  {
   //   methods.Add(m);
   //  }
   // }
   //}

   //methods.Add(module.EntryPoint);

   #endregion

   foreach(var m in Targets)
   {
    methods.Add(m);
   }

   if (methods.Count > 0)
   {
    var ca = new CustomAttribute((ICustomAttributeType)module.Import(ctor));
    ca.ConstructorArguments.Add(new CAArgument(module.CorLibTypes.String, vr.RuntimeModule.Assembly.Name.String));
    module.Assembly.CustomAttributes.Add(ca);
   }

   foreach (var entry in new Scanner(module, methods).Scan())
   {
    if (entry.Item2)
    {
     anno.Set(entry.Item1, ExportKey, ExportKey);
    }
   }

   string eddyType = context.random_generator.GenerateString();

   vr = anno.Get<Virtualizer>(context, VirtualizerKey);

   var refRepl = new Dictionary<IMemberRef, IMemberRef>();

   var oldType = module.GlobalType;
   var newType = new TypeDefUser(oldType.Name);
   oldType.Name = eddyType;
   oldType.BaseType = module.CorLibTypes.GetTypeRef("System", "Object");
   module.Types.Insert(0, newType);

   var old_cctor = oldType.FindOrCreateStaticConstructor();
   var cctor = newType.FindOrCreateStaticConstructor();
   old_cctor.Name = eddyType;
   old_cctor.IsRuntimeSpecialName = false;
   old_cctor.IsSpecialName = false;
   old_cctor.Access = MethodAttributes.PrivateScope;
   cctor.Body = new CilBody(true, new List<Instruction>
            {
                Instruction.Create(OpCodes.Call, old_cctor),
                Instruction.Create(OpCodes.Ret)
            }, new List<ExceptionHandler>(), new List<Local>());


   for (var i = 0; i < oldType.Methods.Count; i++)
   {
    var nativeMethod = oldType.Methods[i];
    if (nativeMethod.IsNative)
    {
     var methodStub = new MethodDefUser(nativeMethod.Name, nativeMethod.MethodSig.Clone());
     methodStub.Attributes = MethodAttributes.Assembly | MethodAttributes.Static;
     methodStub.Body = new CilBody();
     methodStub.Body.Instructions.Add(new Instruction(OpCodes.Jmp, nativeMethod));
     methodStub.Body.Instructions.Add(new Instruction(OpCodes.Ret));

     oldType.Methods[i] = methodStub;
     newType.Methods.Add(nativeMethod);
     refRepl[nativeMethod] = methodStub;
    }
   }

   methods.Add(old_cctor);

   var compression = new Compression();

   compression.TryGetRuntimeDecompressor(module, def =>
   {
    if (def is MethodDef)
     methods.Remove((MethodDef)def);
   });

   var toProcess = new Dictionary<ModuleDef, List<MethodDef>>();

   foreach (var entry in new Scanner(module, methods).Scan())
   {
    var isExport = entry.Item2;
    isExport |= anno.Get<object>(entry.Item1, ExportKey) != null;

    vr.AddMethod(entry.Item1, isExport);
    toProcess.AddListEntry(entry.Item1.Module, entry.Item1);

   }



   context.CurrentModuleWriterListener.OnWriterEvent += new Listener
   {
    Runtime = RuntimeModule,
    context = context,
    vr = vr,
    mod = module,
    methods = toProcess,
    refRepl = refRepl
   }.OnWriterEvent;

  }

 }

 class Listener
 {
  private IModuleWriterListener commitListener;
  public ProtectorContext context;
  public ModuleDef mod;
  public Dictionary<ModuleDef, List<MethodDef>> methods;
  public Dictionary<IMemberRef, IMemberRef> refRepl;
  public ModuleDefMD Runtime;
  public Virtualizer vr;

  public void OnWriterEvent(object sender, ModuleWriterListenerEventArgs e)
  {
   var writer = (ModuleWriter)sender;
   if (commitListener != null)
    commitListener.OnWriterEvent(writer, e.WriterEvent);

   if (e.WriterEvent == ModuleWriterEvent.MDBeginWriteMethodBodies && methods.ContainsKey(writer.Module))
   {

    vr.ProcessMethods(writer.Module, (num, total) =>
    {
    });

    foreach (var repl in refRepl)
    {
     vr.Runtime.Descriptor.Data.ReplaceReference(repl.Key, repl.Value);
    }

    commitListener = vr.CommitModule((ModuleDefMD)mod, (num, total) =>
    {
    });

   }

   //if (e.WriterEvent == ModuleWriterEvent.Begin)
   //{
   // var w = (ModuleWriterBase)writer;
   // w.TheOptions.MetaDataOptions.Flags = MetaDataFlags.PreserveAllMethodRids;
   //}

   //if(e.WriterEvent == ModuleWriterEvent.End)
   //{
   // if(AntiTamper.AntiTamperProtection.AntitampersUsed == 2)
   // {
   //  new RuntimeBinder().BindRuntimeBinaries(context.VmNameAndBinary.Values.ToList(), mod, context);
   // } 
   //}

   string rtName = null;
   byte[] rtBinary = null;

   vr.SaveRuntime(out rtName, out rtBinary);

   if (rtBinary != null && rtName != null)
   {
    try
    {
     context.VmNameAndBinary.Add(rtName, rtBinary);
    }
    catch
    {

    }
   }

  }
 }


}
