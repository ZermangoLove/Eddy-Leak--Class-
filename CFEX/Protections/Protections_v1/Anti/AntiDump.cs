/* Codded by: Eddy^CZ 2018 
   Date: 15.12.2018
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Eddy_Protector_Protections.Protections.Anti
{
 public class AntiDumpProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "AntiDump protection is proteciong that causing unable do get program from memory";
  public override string Id => Author + ".AntiDump";
  public override string Name => "AntiDump";

  public override void Execute(Context ctx)
  {
   TypeDef rtType = Utils.GetRuntimeType("Eddy_Protector_Runtime.AntiDump");
   IEnumerable<IDnlibDef> members = InjectHelper.Inject(rtType, ctx.CurrentModule.GlobalType, ctx.CurrentModule);
   MethodDef cctor = ctx.CurrentModule.GlobalType.FindOrCreateStaticConstructor();
   MethodDef init = (MethodDef)members.Single(method => method.Name == "Initialize2");

   MethodDef vmprotect = (MethodDef)members.Single(method => method.Name == "__");

   vmprotect.Name = ctx.generator.GenerateNewNameChinese();

   init.Name = ctx.generator.GenerateNewNameChinese();

   //ctx.runtime_protect.runtime_intmath.DoIntMath(init, ctx);

   //ctx.runtime_protect.runtime_bignumber.DoProtect(ctx, init);

   //ctx.runtime_protect.runtime_keyshider.DoKeysHide(init, ctx);

   //ctx.runtime_protect.runtime_mutation.DoMutation(init, ctx);

   //ctx.runtime_protect.runtime_refproxy2.DoRefProxy2(init, ctx);

   //ctx.runtime_protect.runtime_controlflow2.DoControlFlow(init, ctx);  

   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));


  }
 }
}
