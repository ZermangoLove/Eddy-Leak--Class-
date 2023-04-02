/* Codded by: Eddy^CZ 2018 
   Date: 15.12.2018
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.IO;
using dnlib.DotNet.Writer;

namespace Eddy_Protector.Protections.Calli
{
 class CalliProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Hide call to calli";
  public override string Id => Author+".Calli";
  public override string Name => "Calli";

  public override void Execute(Context ctx)
  {
   foreach (var m in ctx.analyzer.targetCtx.methods_usercode)
   {
    var calli = new RuntimeCalliProtection();
    calli.DoCalliProtect(m, ctx);
   }
  } 
 }

 class RuntimeCalliProtection
 {

  public static int token2 = 0;
  public static List<MemberRef> listmember = new List<MemberRef>();
  public static List<int> listtoken = new List<int>();

  public void DoProtect(MethodDef method, Context ctx)
  {
   DoCalliProtect(method, ctx);
  }

  public void DoCalliProtect(MethodDef method, Context ctx)
  {

   TypeDef typeDef = Utils.GetRuntimeType("Confuser.Runtime.CalliInj");

   IEnumerable<IDnlibDef> members = InjectHelper.Inject(typeDef, ctx.CurrentModule.GlobalType, ctx.CurrentModule);

   MethodDef init = (MethodDef)members.Single(m => m.Name == "ResolveToken");
   init.Name = ctx.generator.GenerateNewName();

   //My adding to get new type for each proccesed method!
   TypeDefUser NewType = new TypeDefUser(ctx.generator.GenerateNewName(),
ctx.CurrentModule.CorLibTypes.Object.TypeDefOrRef);

   NewType.Attributes = TypeAttributes.NotPublic |
    TypeAttributes.AutoLayout |
        TypeAttributes.Class |
        TypeAttributes.AnsiClass;

   init.DeclaringType = null;
   ctx.CurrentModule.Types.Add(NewType);
   NewType.Methods.Add(init);
   //End of adding

   int KEY = ctx.generator.RandomInt();

   MutationHelper.InjectKeys(init,
                      new[] { 0 },

                      new int[] { KEY });

   //ctx.runtime_protect.runtime_controlflow1.DoControlFlow(init, ctx);   
   ctx.runtime_protect.runtime_mutation.DoMutation(init, ctx);
   ctx.runtime_protect.runtime_refproxy2.DoRefProxy2(init, ctx);
   ctx.runtime_protect.runtime_controlflow1.DoControlFlow(init, ctx);


   if (!method.HasBody) return;
   if (method == init) return;

   for (int i = 0; i < method.Body.Instructions.Count - 1; i++)
   {
    if (method.Body.Instructions[i].OpCode == OpCodes.Call || method.Body.Instructions[i].OpCode == OpCodes.Callvirt)
    {
     try
     {
      var member = method.Body.Instructions[i].Operand;

      MemberRef membertocalli = (MemberRef)member;

      token2 = membertocalli.MDToken.ToInt32() ^ KEY;

      ctx.logger.Progress("Calli" + " - Protecting member: " + membertocalli.FullName);

      if (membertocalli.ToString().Contains("ResolveToken")) break;
      if (membertocalli.HasThis) break;
      if (listmember.Contains(membertocalli)) break;
      if (listtoken.Contains(token2)) break;

      if (listmember.Contains(membertocalli))
      {
       method.Body.Instructions[i].OpCode = OpCodes.Calli;
       method.Body.Instructions[i].Operand = membertocalli.MethodSig;
       method.Body.Instructions.Insert(i, Instruction.Create(OpCodes.Call, init));
       method.Body.Instructions.Insert(i, Instruction.Create(OpCodes.Ldc_I4, token2));
      }
      else
      {
       MethodSig MethodSign = membertocalli.MethodSig;

       method.Body.Instructions[i].OpCode = OpCodes.Calli;
       method.Body.Instructions[i].Operand = MethodSign;
       method.Body.Instructions.Insert(i, Instruction.Create(OpCodes.Call, init));
       method.Body.Instructions.Insert(i, Instruction.CreateLdcI4(token2));
       listmember.Add(membertocalli);
       listtoken.Add(token2);
      }
     }
     catch (Exception e)
     {
      //ctx.logger.Error(e.Message);
     }
    }
   }
  }

 }

}
