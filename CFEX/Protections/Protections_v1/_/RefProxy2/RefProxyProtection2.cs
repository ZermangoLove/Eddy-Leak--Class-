using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet;

namespace Eddy_Protector.Protections.RefProxy2
{
	class RefProxy2 : ProtectionPhase
	{
		public override string Author => Engine.Author;
		public override string Description => "Hide calls in assembly based on Panda Obfuscator";
		public override string Id => Author+".RefProxy2";
		public override string Name => "RefProxy2";

  public List<MethodDef> Targets = new List<MethodDef>();

  public RefProxy2(object targets)
  {
   Targets = targets as List<MethodDef>;
  }


		public override void Execute(Context ctx)
		{
			ctx.logger.Info("Reference proxy 2 started..");
			var ref_proxy = new RuntimeRefProxy2();

			foreach (MethodDef method in Targets)
			{
    ctx.logger.Progress(Name+" - Processing method: "+method.Name);
				ref_proxy.DoRefProxy2(method,ctx);
			}		

			ctx.logger.Info("Reference proxy 2 finished..");
		}
	}

	class RuntimeRefProxy2
	{
		public void DoRefProxy2(MethodDef method,Context ctx)
		{
			var rf = new RPNormal();

			rf.Execute(method, ctx);

		}
	}

}
