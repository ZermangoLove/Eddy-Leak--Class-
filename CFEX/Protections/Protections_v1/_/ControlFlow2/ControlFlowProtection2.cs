using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using Confuser.DynCipher;
using dnlib.DotNet;
using dnlib.DotNet.MD;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace Eddy_Protector.Protections.ControlFlow2
{
	class ControlFlowProtection2 : ProtectionPhase
	{
		public override string Author => Engine.Author;
		public override string Description => "Control flow protection base on ConfuserEx";
		public override string Id => Author+".ControlFlow2";
		public override string Name => "ControlFlow2";


		public override void Execute(Context ctx)
		{
			var runtime_controlflow = new RuntimeControlFlowProtection2(ctx);

			foreach (MethodDef method in ctx.analyzer.targetCtx.methods_usercode)
			{
    //if (method.DeclaringType == ctx.CurrentModule.GlobalType) continue;
				runtime_controlflow.DoControlFlow(method, ctx);
			}
			
		}

	}

	class RuntimeControlFlowProtection2
	{


		private static readonly JumpMangler Jump = new JumpMangler();
		private static readonly SwitchMangler Switch = new SwitchMangler();

  private static CFContext CFContext;

  public RuntimeControlFlowProtection2(Context ctx)
  {
   byte[] newSeed = ctx.generator.RandomBytes(32);
   var random = new RandomGenerator(newSeed);

   CFContext ret = new CFContext();
   ret.Type = CFType.Switch;
   ret.Predicate = PredicateType.Expression;
   int rawIntensity = 1;
   //ret.Intensity = (double)rawIntensity / 100.0;
   ret.Intensity = 1;
   ret.Depth = 4;
   ret.JunkCode = true;
   ret.Random = random;
   ret.context = ctx;
   ret.DynCipher = new DynCipherService();
   CFContext = ret;
  }


		public void DoControlFlow(MethodDef method,Context ctx)
		{

   var ret = CFContext;

   ret.Method = method;

   if (ret.Predicate == PredicateType.x86 && (ctx.CurrentModule.Cor20HeaderFlags & ComImageFlags.ILOnly) != (ComImageFlags)0u)
   {
    ctx.CurrentModuleWriterOptions.Cor20HeaderOptions.Flags &= ~ComImageFlags.ILOnly;
   }

   if (method.HasBody && (method.Body.Instructions.Count > 0))
			{
				for (int a = 0; a < 5; a++) //1x repeat
				{
     ctx.logger.Progress("Processing control flow 2 on method: "+method.Name);
					ProcessMethod(method.Body, ret);
				}
				
			}

		}
		private static ManglerBase GetMangler(CFType type)
		{
			if (type == CFType.Switch)
			{
				return Switch;
			}
			return Jump;
		}

		private void ProcessMethod(CilBody body, CFContext ctx)
		{
			uint num;
			if (!MaxStackCalculator.GetMaxStack(body.Instructions, body.ExceptionHandlers, out num))
			{
				throw new NotImplementedException(null);
			}
			body.MaxStack = (ushort)num;
			ScopeBlock root = BlockParser.ParseBody(body);
			GetMangler(ctx.Type).Mangle(body, root, ctx);
			body.Instructions.Clear();
			root.ToBody(body);
			foreach (ExceptionHandler handler in body.ExceptionHandlers)
			{
				int num2 = body.Instructions.IndexOf(handler.TryEnd) + 1;
				handler.TryEnd = (num2 < body.Instructions.Count) ? body.Instructions[num2] : null;
				num2 = body.Instructions.IndexOf(handler.HandlerEnd) + 1;
				handler.HandlerEnd = (num2 < body.Instructions.Count) ? body.Instructions[num2] : null;
			}
			body.KeepOldMaxStack = true;
		}


	}
}
