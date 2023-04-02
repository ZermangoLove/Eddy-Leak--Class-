using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using Eddy_Protector.Core;

namespace Eddy_Protector.Protections.MathMutate
{
	class MathProtection : ProtectionPhase
	{
		public override string Author => Engine.Author;
		public override string Description => "Hide constants to various math oprtations";
		public override string Id => Author+".MathMutate";
		public override string Name => "MathMutate";


		public override void Execute(Context ctx)
		{
			var math_runtime = new RuntimeMathProtection();

			foreach (MethodDef method in ctx.analyzer.targetCtx.methods_usercode)
			{
				ctx.logger.Progress(Name + "Processing method: "+ method.Name);
				math_runtime.DoMathProtection(method,ctx);
			}

		}
	}

	class RuntimeMathProtection
	{
		public void DoMathProtection(MethodDef method, Context ctx)
		{
			var math_context = new MathContext.Arithmetic(ctx.CurrentModule);

			math_context.Execute(method);

		}
	}

}
