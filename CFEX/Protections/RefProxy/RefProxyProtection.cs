using System.Collections.Generic;
using System.Linq;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Eddy_Protector_Ciphering;
using dnlib.DotNet.MD;

using Protector.Protections;
using Protector.Helpers;
using dnlib.DotNet.Writer;
using Protector.Handler;
using System.IO;
using System;
using Protector.Protections.IntMath;
using Protector.Protections.RefProxy2;

namespace Protector.Protections.RefProxy
{
 class RefProxyProtection
 {

  public ModuleDef Execute(ModuleDef module,ProtectorContext context)
  {


   //context.CurrentModuleWriterListener = new ModuleWriterListener();
   //context.CurrentModuleWriterOptions = new ModuleWriterOptions(module, context.CurrentModuleWriterListener);

   var refproxy_runtime = new RuntimeRefProxyProtection1(module,context);

   //var targets = SearchTargets(module);

   //foreach (var method in targets)
   //{
   // if (method.Name == "InitializeComponent" || method.DeclaringType == module.GlobalType) continue;
   // if (method.HasBody)
   // {
   //  refproxy_runtime.DeRefProxy(method, context);
   // }

   //}

   refproxy_runtime.DeRefProxy(module.EntryPoint, context);

   refproxy_runtime.Finalize(context);

   return module;

  }


  public List<MethodDef> SearchTargets(ModuleDef module)
  {
   List<MethodDef> targets = new List<MethodDef>();

   foreach (var t in module.GetTypes())
   {
    foreach (var m in t.Methods)
    {
     if (!m.IsConstructor)
     {
      targets.Add(m);
     }
    }
   }
   return targets;
  }


 }

 class RuntimeRefProxyProtection1
 {
  class RPStore
  {
   public readonly Dictionary<MethodSig, TypeDef> delegates = new Dictionary<MethodSig, TypeDef>(new MethodSigComparer());
   public ExpressionEncoding expression;
   public MildMode mild;

   public NormalEncoding normal;
   public RandomGenerator random;
   public StrongMode strong;
   public x86Encoding x86;
  
   class MethodSigComparer : IEqualityComparer<MethodSig>
   {
    public bool Equals(MethodSig x, MethodSig y)
    {
     return new SigComparer().Equals(x, y);
    }

    public int GetHashCode(MethodSig obj)
    {
     return new SigComparer().GetHashCode(obj);
    }
   }
  }

  public ModuleDef CurrentModule;
  RPStore rpStore;
  RPContext rpContext;
  ProtectorContext Context;
  public RuntimeRefProxyProtection1(ModuleDef mod, ProtectorContext context)
  {
   CurrentModule = mod;
   Context = context;

   byte[] newSeed = context.random_generator.RandomBytes(32);
   var random = new RandomGenerator(newSeed);

   var store = new RPStore { random = random };

   //context.RequestNative();

   var ret = new RPContext();
   ret.Mode = Mode.Strong;
   ret.Encoding = EncodingType.Expression;
   ret.InternalAlso = true;
   ret.TypeErasure = true;
   ret.Depth = 5;
   ret.InitCount = 1;
   ret.ctx = context;
   ret.DynCipher = new DynCipherService();
   ret.Random = store.random;
   ret.Delegates = store.delegates;
   ret.RuntimeMethods = new List<MethodDef>();
   ret.CCargs = new List<CAArgument>();

   ret.EncodingHandler = new ExpressionEncoding();
   ret.ModeHandler = store.strong ?? (store.strong = new StrongMode());

   if ((CurrentModule.Cor20HeaderFlags & ComImageFlags.ILOnly) != 0)
    ret.ctx.CurrentModuleWriterOptions.Cor20HeaderOptions.Flags &= ~ComImageFlags.ILOnly;

   rpStore = store;
   rpContext = ret;
  }

  public void DeRefProxy(MethodDef method, ProtectorContext context)
  {
  

   if (method.HasBody && method.Body.Instructions.Count > 0)
   {

    rpContext.Module = method.Module;
    rpContext.Method = method;
    rpContext.Body = method.Body;
    rpContext.BranchTargets = new HashSet<Instruction>(method.Body.Instructions.Select(instr => instr.Operand as Instruction).Concat(method.Body.Instructions.Where(instr => instr.Operand is Instruction[]).SelectMany(instr => (Instruction[])instr.Operand)).Where(target => target != null));

    ProcessMethod(rpContext);
   }
  }

  public void Finalize(ProtectorContext context)
  {
   rpStore.strong.Finalize(rpContext);
   MutateRuntimeMethods(rpContext, context); 
  }

  public void MutateRuntimeMethods(RPContext ret, ProtectorContext ctx)
  {
   foreach (MethodDef method in ret.RuntimeMethods)
   {
    if (method.IsConstructor) continue;
    new RuntimeIntMathProtection().Protect(method);   
    new MutationProtection().Mutate3(method);
   }
   foreach (MethodDef method in ret.RuntimeMethods)
   {
    if (method.IsConstructor) continue;  
    new RuntimeRefProxy2().DoRefProxy2(method, ctx);
    new MutationProtection().Mutate7(method);
    new ControlFlow.ControlFlow(method.Module).DoControlFlow(method, ctx);
   }

   foreach (MethodDef method in ret.RuntimeMethods)
   {
    if (method.IsConstructor)
    {
     //ctx.runtime_protect.runtime_antidnspy.DoAntiDnspy(method, ctx);
    }
   }
  }


   public void ProcessMethod(RPContext ctx)
  {
   for (int i = 0; i < ctx.Body.Instructions.Count; i++)
   {
    Instruction instr = ctx.Body.Instructions[i];
    if (instr.OpCode.Code == Code.Call || instr.OpCode.Code == Code.Callvirt || instr.OpCode.Code == Code.Newobj)
    {
     var operand = (IMethod)instr.Operand;
     var def = operand.ResolveMethodDef();

     if (instr.OpCode.Code != Code.Newobj && operand.Name == ".ctor")
      continue;
     if (operand is MethodDef && !ctx.InternalAlso)
      continue;
     if (operand is MethodSpec)
      continue;
     if (operand.DeclaringType is TypeSpec)
      continue;
     if (operand.MethodSig.ParamsAfterSentinel != null &&
      operand.MethodSig.ParamsAfterSentinel.Count > 0)
      continue;
     TypeDef declType = operand.DeclaringType.ResolveTypeDef();

     if (declType != null)
     {
      if (declType.IsDelegate())
       continue;
      if (declType.IsValueType && operand.MethodSig.HasThis)
       return;
     }


     //No prefixed call
     if (i - 1 >= 0 && ctx.Body.Instructions[i - 1].OpCode.OpCodeType == OpCodeType.Prefix)
      continue;

     ctx.ModeHandler.ProcessCall(ctx, i);
    }
   }
  }

 }


}
