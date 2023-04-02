using System.Collections.Generic;
using System.Linq;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Eddy_Protector_Ciphering;
using dnlib.DotNet.MD;

namespace Eddy_Protector_Protections.Protections.RefProxy
{
 public class RefProxyProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Hide all call to special reference proxy based on ConfuserEx";
  public override string Id => Author + ".RefProxy";
  public override string Name => "RefProxy";

  //RPContext rpContext;
  //RPStore store;



  public override void Execute(Context context)
  {

   var refproxy_runtime = new RuntimeRefProxyProtection1();

   foreach (MethodDef method in context.analyzer.targetCtx.methods_usercode)
   {
    if (method.Name == "InitializeComponent" || method.DeclaringType == context.CurrentModule.GlobalType) continue;
    refproxy_runtime.DeRefProxy(method, context);
   }

  }


 }
 public class RuntimeRefProxyProtection1
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

  public void DeRefProxy(MethodDef method, Context context)
  {
   byte[] newSeed = context.generator.RandomBytes(32);
   var random = new RandomGenerator(newSeed);

   var store = new RPStore { random = random };

   //context.RequestNative();

   var ret = new RPContext();
   ret.Mode = Mode.Strong;
   ret.Encoding = EncodingType.Expression;
   ret.InternalAlso = true;
   ret.TypeErasure = false;
   ret.Depth = 6;
   ret.InitCount = 1;
   ret.ctx = context;
   ret.DynCipher = new DynCipherService();
   ret.Random = store.random;
   ret.Delegates = store.delegates;
   ret.RuntimeMethods = new List<MethodDef>();
   ret.CCargs = new List<CAArgument>();
  
   ret.EncodingHandler = store.expression ?? (store.expression = new ExpressionEncoding());
   ret.ModeHandler = store.strong ?? (store.strong = new StrongMode());

   if ((ret.ctx.CurrentModule.Cor20HeaderFlags & ComImageFlags.ILOnly) != 0)
    ret.ctx.CurrentModuleWriterOptions.Cor20HeaderOptions.Flags &= ~ComImageFlags.ILOnly;

   if (method.HasBody && method.Body.Instructions.Count > 0)
   {

    ret.Module = method.Module;
    ret.Method = method;
    ret.Body = method.Body;
    ret.BranchTargets = new HashSet<Instruction>(method.Body.Instructions.Select(instr => instr.Operand as Instruction).Concat(method.Body.Instructions.Where(instr => instr.Operand is Instruction[]).SelectMany(instr => (Instruction[])instr.Operand)).Where(target => target != null));

    ProcessMethod(ret);
   }

   store.strong.Finalize(ret);

   MutateRuntimeMethods(ret, context);
  }

  public void MutateRuntimeMethods(RPContext ret, Context ctx)
  {
   foreach (MethodDef method in ret.RuntimeMethods)
   {
    if (method.IsConstructor) continue;

    ctx.runtime_protect.runtimeControlFlow2.DoControlFlow(method, ctx);
   }
   foreach (MethodDef method in ret.RuntimeMethods)
   {
    if (method.IsConstructor) continue;
    ctx.runtime_protect.runtime_intmath.DoIntMath(method, ctx);
    ctx.runtime_protect.runtime_refproxy2.DoRefProxy2(method, ctx);
   }

   foreach (MethodDef method in ret.RuntimeMethods)
   {
    if (method.IsConstructor)
    {
     ctx.runtime_protect.runtime_antidnspy.DoAntiDnspy(method,ctx);

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
