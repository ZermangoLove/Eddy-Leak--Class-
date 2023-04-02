/* Codded by: Eddy^CZ 2018 
   Date: 15.12.2018
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;

namespace Eddy_Protector_Protections.Protections.AntiTamper
{
	public class AntiTamper : ProtectionPhase
	{
		public override string Author => Engine.Author;
		public override string Description => "Anti tamper protection";
		public override string Id => Author+".AntiTamper";
		public override string Name => "Anti tamper";

		public override void Execute(Context ctx)
		{
			var runtime_antitamper = new RuntimeAntiTamperProtection();

   /* Antitamper is codded to protect all posible methods in assembly */

			List<MethodDef> targets = new List<MethodDef>();

			foreach(var t in ctx.CurrentModule.GetTypes())
			{
				foreach(var m in t.Methods)
				{
					if(!m.IsConstructor/* && m.DeclaringType == ctx.CurrentModule.GlobalType*/)
					{
						targets.Add(m);
					}					
				}
			}
   foreach (var m in ctx.analyzer.targetCtx.methods_targets)
   {
    if (!m.IsConstructor)
    {
     targets.Add(m);
    }
   }

   runtime_antitamper.DoAntiTamperProtecton(targets,ctx);
		}
	}


	public class RuntimeAntiTamperProtection
	{
		public void DoAntiTamperProtecton(List<MethodDef> methods,Context ctx)
		{
			var normal = new NormalMode();
			IModeHandler mode = normal;
			mode.HandleInject(ctx);
			mode.HandleMD(methods,ctx);
		}
	}

}
