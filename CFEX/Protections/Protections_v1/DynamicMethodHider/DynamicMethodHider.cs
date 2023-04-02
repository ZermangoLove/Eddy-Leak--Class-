using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;

namespace Eddy_Protector_Protections.Protections.DynamicMethodHider
{
 public class DynamicMethodHider : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Hide methods to Dynamic Methods";
  public override string Id => Author+"DynamicMethodHider";
  public override string Name => "DynamicMethodHider";

  public override void Execute(Context ctx)
  {
   var p = new DynamicMethodProcessor();

   p.Initialize(ctx.analyzer.targetCtx.Module_mono.Assembly, ctx);
   
   foreach(var t in ctx.analyzer.targetCtx.Module_mono.Types)
   {
    foreach(var m in t.Methods)
    {
     p.Execute(m);
    }
   }

  }
 }
}
