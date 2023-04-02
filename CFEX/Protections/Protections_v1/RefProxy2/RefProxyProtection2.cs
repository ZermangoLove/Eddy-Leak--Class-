using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;

namespace Eddy_Protector_Protections.Protections.RefProxy2
{
	public class RefProxy2 : ProtectionPhase
	{
		public override string Author => Engine.Author;
		public override string Description => "Hide calls in assembly based on Panda Obfuscator";
		public override string Id => Author+".RefProxy2";
		public override string Name => "RefProxy2";


		public override void Execute(Context ctx)
		{
			var ref_proxy = new RuntimeRefProxy2();

			foreach (MethodDef method in ctx.analyzer.targetCtx.methods_usercode)
			{
				ref_proxy.DoRefProxy2(method,ctx);
			}		

		}
	}

	public class RuntimeRefProxy2
	{
		public void DoRefProxy2(MethodDef method,Context ctx)
		{
			var rf = new RPNormal();

			rf.Execute(method, ctx);

		}
	}

}
