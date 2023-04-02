using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet.Emit;
using dnlib.DotNet;

namespace Eddy_Protector.Protections.ModuleFlood
{
 class ModuleFloodProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;

  public override string Description => "Floods cctor to confuse";

  public override string Id => Author+".ModuleFloodProtection";

  public override string Name => "ModuleFloodProtection";

  public override void Execute(Context ctx)
  {
   TypeDef rtType = Utils.GetRuntimeType("Confuser.Runtime.ModuleFlood");

   var module = ctx.CurrentModule;

   for (int a = 0; a < 256; a++)
   {
    IEnumerable<IDnlibDef> members = InjectHelper.Inject(rtType, module.GlobalType, module);
    MethodDef cctor = module.GlobalType.FindStaticConstructor();
    MethodDef init = (MethodDef)members.Single((IDnlibDef method) => method.Name == "Initialize0");
    init.Name = ctx.generator.GenerateNewName();
    ctx.runtime_protect.runtime_controlflow1.DoControlFlow(init, ctx);
    ctx.runtime_protect.runtime_antidnspy.DoAntiDnspy(init, ctx);
    cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));
   }

  }
 }
}
