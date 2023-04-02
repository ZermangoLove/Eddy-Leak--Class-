using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Eddy_Protector.Protections.Mutation
{
	class MutationProtection : ProtectionPhase
	{
		public override string Author => Engine.Author;

		public override string Description => "Mutate all contants in assembly, based on Mighty mutation algo.";

		public override string Id => Author+".Mutation";

		public override string Name => "Mutation";


		public override void Execute(Context ctx)
		{

			foreach (MethodDef method in ctx.analyzer.targetCtx.methods_usercode)
			{
				for(int i = 0; i < 1; i++) //2x Repeat
				{
					ctx.logger.Progress(String.Format(Name+" - Mutating  : {0}", method.Name));
					DoMutation(method, ctx);					
				}
			}

		}
		public void DoMutation(MethodDef method, Context ctx)
		{
			if (!method.HasBody) return;

			CilBody body = method.Body;
			IList<Instruction> instructions = body.Instructions;


			for (int i = 0; i < instructions.Count; i++)
			{
				if (instructions[i].IsLdcI4())
				{
					if (!Utils.CanObfuscateLDCI4(instructions, i)) continue;
					int forward = 0;
					new MutateStageProcessor(instructions, i).Mutate(ref forward);
					i += forward;
				}
			}

			for (int i = 0; i < instructions.Count; i++)
			{
				if (instructions[i].IsLdcI4())
				{
					if (!Utils.CanObfuscateLDCI4(instructions, i)) continue;
					int forward = 0;
					new SecondReplaceStageProcessor(ctx.CurrentModule, body, i).Replace(ref forward);
					i += forward;
				}
			}
		}
	}

	class RuntimeMutation
	{
		public void DoMutation(MethodDef method, Context ctx)
		{
			if (!method.HasBody) return;

			CilBody body = method.Body;
			IList<Instruction> instructions = body.Instructions;


			for (int i = 0; i < instructions.Count; i++)
			{
				if (instructions[i].IsLdcI4())
				{
					if (!Utils.CanObfuscateLDCI4(instructions, i)) continue;
					int forward = 0;
					new MutateStageProcessor(instructions, i).Mutate(ref forward);
					i += forward;
				}
			}

			for (int i = 0; i < instructions.Count; i++)
			{
				if (instructions[i].IsLdcI4())
				{
					if (!Utils.CanObfuscateLDCI4(instructions, i)) continue;
					int forward = 0;
					new SecondReplaceStageProcessor(ctx.CurrentModule, body, i).Replace(ref forward);
					i += forward;
				}
			}
		}
	}
}
