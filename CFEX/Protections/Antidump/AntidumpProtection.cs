using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Protector.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Protector.Protections.Antidump
{
 class AntidumpProtection
 {
  public ModuleDef AddAntidump(ModuleDef module, ProtectorContext ctx)
  {

   /* Get runtime type */
   TypeDef rtType = DnLibHelper.GetRuntimeType("Protector.Runtime.AntiDump");

   /* Inject method */
   IEnumerable<IDnlibDef> members = members = InjectHelper.Inject(rtType, module.GlobalType, module);
  

   /* Methods */
   MethodDef cctor = module.GlobalType.FindOrCreateStaticConstructor();
   MethodDef init = (MethodDef)members.Single(method => method.Name == "Initialize2");
   MethodDef vmprotect = (MethodDef)members.Single(method => method.Name == "__");

   /* Names */
   vmprotect.Name = ctx.random_generator.GenerateString();
   init.Name = ctx.random_generator.GenerateString();

   /* Instructions */
   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));


   return module;
  }
 }
}
