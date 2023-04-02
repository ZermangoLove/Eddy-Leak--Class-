using System.Collections.Generic;
using System.Linq;
using Eddy_Protector.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Confuser.DynCipher;
using dnlib.DotNet.MD;

namespace Eddy_Protector.Protections.RefProxy
{
 class RefProxyProtection : ProtectionPhase
 {
  public override string Author => "EddyCZ";
  public override string Description => "Hide all call to special reference proxy";
  public override string Id => "EddyCZ.RefProxy";
  public override string Name => "RefProxy";

  RPContext rpContext;
  RPStore store;

  class RPStore
  {
   public readonly Dictionary<MethodSig, TypeDef> delegates = new Dictionary<MethodSig, TypeDef>(new MethodSigComparer());
   public ExpressionEncoding expression;
   public MildMode mild;

   public NormalEncoding normal;
   public RandomGenerator random;
   public StrongMode strong;
   public x86Encoding x86;
   public ExpressionEncoding Expression;

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

  public RPContext Initialize(Context context)
  {
   byte[] newSeed = context.generator.RandomBytes(32);
   var random = new RandomGenerator(newSeed);

   store = new RPStore { random = random };

   context.RequestNative();

   var ret = new RPContext();
   ret.Mode = Mode.Strong;
   ret.Encoding = EncodingType.x86;
   ret.InternalAlso = true;
   ret.TypeErasure = false;
   ret.Depth = 6;
   ret.InitCount = 6;
   ret.ctx = context;
   ret.DynCipher = new DynCipherService();
   ret.Random = store.random;
   ret.Delegates = store.delegates;
   ret.RuntimeMethods = new List<MethodDef>();
   ret.CCargs = new List<CAArgument>();

   ret.EncodingHandler = store.x86 ?? (store.x86 = new x86Encoding());
   ret.ModeHandler = store.strong ?? (store.strong = new StrongMode());

   if ((ret.ctx.CurrentModule.Cor20HeaderFlags & ComImageFlags.ILOnly) != 0)
   {
    ret.ctx.CurrentModuleWriterOptions.Cor20HeaderOptions.Flags &= ~ComImageFlags.ILOnly;
   }

   return ret;
  } 

  public override void Execute(Context context)
  {

   var ret = Initialize(context);

   /* Process only runtime methods */

   foreach (TypeDef t in context.CurrentModule.GlobalType.GetTypes())
   {
    foreach (MethodDef method in t.Methods)
    {
     if (method.HasBody && method.Body.Instructions.Count > 0)
     {
      context.logger.Progress("Proccessing method: " + method.Name);

      ret.Module = method.Module;
      ret.Method = method;
      ret.Body = method.Body;
      ret.BranchTargets = new HashSet<Instruction>(method.Body.Instructions.Select(instr => instr.Operand as Instruction).Concat(method.Body.Instructions.Where(instr => instr.Operand is Instruction[]).SelectMany(instr => (Instruction[])instr.Operand)).Where(target => target != null));

      ProcessMethod(ret);
     }
     store.strong.Finalize(ret);
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
       continue;
     }
     else
     {
      continue;
     }


     //No prefixed call
     if (i - 1 >= 0 && ctx.Body.Instructions[i - 1].OpCode.OpCodeType == OpCodeType.Prefix)
      continue;

     ctx.ModeHandler.ProcessCall(ctx, i);
    }
   }
  }


 }
 class RuntimeRefProxyProtection1
 {





 }
}
