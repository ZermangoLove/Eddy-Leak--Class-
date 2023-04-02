using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using Eddy_Protector.Virtualization;

using Eddy_Protector_Core;
using System.IO;
using System.Runtime.CompilerServices;
using dnlib.DotNet.Writer;
using dnlib.DotNet.Emit;

namespace Eddy_Protector_Protections.Protections.Virtualization
{
 public class VirtualizationProtect : ProtectionPhase
 {
  public override string Author => "EddyCZ";
  public override string Description => "Virtualization protection";
  public override string Id => "EddyCZ.Virtualization";
  public override string Name => "Virtualization";

  public override void Execute(Context ctx)
  {

   //ctx.analyzer.targetCtx.methods_virtualize.Add(ctx.CurrentModule.GlobalType.FindStaticConstructor());

   Initialize(ctx);
  }


  public static readonly object VirtualizerKey = new object();
  public static readonly object MergeKey = new object();
  public static readonly object ExportKey = new object();


  public void Initialize(Context ctx)
  {
   ModuleDef merge = null;

   string rtName = "_"+Guid.NewGuid().ToString().ToUpper();
   ModuleDefMD RuntimeModule = ModuleDefMD.Load("Eddy_Protector_VM_RT.dll");
   RuntimeModule.Assembly.Name = rtName;
   RuntimeModule.Name = rtName + ".dll";

   var anno = new Annotations();
   var vr = new Virtualizer(ctx.generator.RandomInt(), false);

   vr.Initialize(RuntimeModule);

   anno.Set(ctx, VirtualizerKey, vr);
   anno.Set(ctx, MergeKey, merge);

   vr.CommitRuntime(null);

   

   var ctor = typeof(InternalsVisibleToAttribute).GetConstructor(new[] { typeof(string) });
   var methods = new HashSet<MethodDef>();


   foreach (var method in ctx.analyzer.targetCtx.methods_virtualize)
   {
    methods.Add(method);
   }

   if (methods.Count > 0)
   {
    var ca = new CustomAttribute((ICustomAttributeType)ctx.CurrentModule.Import(ctor));
    ca.ConstructorArguments.Add(new CAArgument(ctx.CurrentModule.CorLibTypes.String, vr.RuntimeModule.Assembly.Name.String));
    ctx.CurrentModule.Assembly.CustomAttributes.Add(ca);
   }

   foreach (var entry in new Scanner(ctx.CurrentModule, methods).Scan())
   {
    if (entry.Item2)
    {
     anno.Set(entry.Item1, ExportKey, ExportKey);
    }
   }

   string eddyType = ctx.generator.GenerateNewNameChinese();

   vr = anno.Get<Virtualizer>(ctx, VirtualizerKey);

   var refRepl = new Dictionary<IMemberRef, IMemberRef>();

   var oldType = ctx.CurrentModule.GlobalType;
   var newType = new TypeDefUser(oldType.Name);
   oldType.Name = eddyType;
   oldType.BaseType = ctx.CurrentModule.CorLibTypes.GetTypeRef("System", "Object");
   ctx.CurrentModule.Types.Insert(0, newType);

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

   compression.TryGetRuntimeDecompressor(ctx.CurrentModule, def =>
   {
    if (def is MethodDef)
     methods.Remove((MethodDef)def);
   });

   var toProcess = new Dictionary<ModuleDef, List<MethodDef>>();

   foreach (var entry in new Scanner(ctx.CurrentModule, methods).Scan())
   {
    var isExport = entry.Item2;
    isExport |= anno.Get<object>(entry.Item1, ExportKey) != null;

    vr.AddMethod(entry.Item1, isExport);
    toProcess.AddListEntry(entry.Item1.Module, entry.Item1);

   }

   

   ctx.CurrentModuleWriterListener.OnWriterEvent += new Listener
   {
    Runtime = RuntimeModule,
    context = ctx,
    vr = vr,
    methods = toProcess,
    refRepl = refRepl
   }.OnWriterEvent;

  }

 }


class Listener
 {
  private IModuleWriterListener commitListener;
  public Context context;
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

    commitListener = vr.CommitModule(context.CurrentModule, (num, total) =>
    {
    });

    

    //foreach (var m in context.methods_virtualize)
    //{
    //	dnlib.DotNet.Writer.MethodBody body = writer.MetaData.GetMethodBody(m);
    //	bool ok = writer.MethodBodies.Remove(body);
    //}

    //foreach (var t in context.moduleDef.GetTypes())
    //{
    //	var m = t.Methods.ToArray();

    //	foreach (var m_tar in context.methods_virtualize)
    //	{
    //		for (int a = 0; a < m.Length; a++)
    //		{
    //			if (m_tar == m[a])
    //			{
    //				t.Methods.Remove(m[a]);
    //			}
    //		}
    //	}
    //}

   }



   else if (commitListener != null && e.WriterEvent == ModuleWriterEvent.End && vr.ExportDbgInfo)
   {
    //var mapName = Path.ChangeExtension(writer.Module.Name, "map");
    //var mapPath = Path.GetFullPath(Path.Combine(ctx.OutputDirectory, mapName));
    //Directory.CreateDirectory(ctx.OutputDirectory);
    //File.WriteAllBytes(mapPath, vr.Runtime.DebugInfo);
   }


   

   vr.SaveRuntime(context.output_dir);


  }
 }

}
