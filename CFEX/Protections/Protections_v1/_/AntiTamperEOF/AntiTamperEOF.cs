using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Reflection;

namespace Eddy_Protector.Protections.AntiTamperEof
{
 class AntiTamperEof : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "This is a special antitamper that can save some data at end of file.";
  public override string Id => Author + ".AntiTamperEOF";
  public override string Name => "AntiTamperEOF";
  public override void Execute(Context ctx)
  {

   /* TEST INJECTION */

   MethodDef injection = Utils.GetRuntimeType("Confuser.Runtime.AntiTamperEof").FindMethod("Initialize");

   //TypeRef t = ctx.CurrentModule.CorLibTypes.GetTypeRef("System", "Int32");

   //var f = new FieldDefUser(ctx.generator.GenerateNewName(), new FieldSig(t.ToTypeSig()));

   //f.Name = "EofKey";
   //f.Attributes = dnlib.DotNet.FieldAttributes.Static;

   //ctx.CurrentModule.GlobalType.Fields.Add(f);

   MethodDef injection_Inst = InjectHelper.Inject(injection, ctx.CurrentModule);

   injection_Inst.Name = ctx.generator.GenerateNewName();

   //int num0 = ctx.generator.RandomInt();
   //int num1 = ctx.generator.RandomInt();
   //int num2 = ctx.generator.RandomInt();
   //int num3 = ctx.generator.RandomInt();
   //int num4 = ctx.generator.RandomInt();
   //int num5 = ctx.generator.RandomInt();
   //int num6 = ctx.generator.RandomInt();
   //int num7 = ctx.generator.RandomInt();
   //int num8 = ctx.generator.RandomInt();
   //int num9 = ctx.generator.RandomInt();
   //int num10 = ctx.generator.RandomInt();
   //int num11 = ctx.generator.RandomInt();
   //int num12 = ctx.generator.RandomInt();
   //int num13 = ctx.generator.RandomInt();

   ///* Expression */
   //int num14 = (num0 % (~(num1 - (num2 * (num3 - (num4 + (num5 + (((num6 * (num7 % num8))))))))) + (num9) ^ (num10) * (num11 / num12 - num13)));

   int result = ctx.AntiTamperEofResult;

   int[] exp = ctx.AntiTamperExpression;

   //int result = (int)Math.Sqrt((double)num14);

   MutationHelper.InjectKeys(injection_Inst,
                         new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 , 15},

                         new int[] {exp[0], exp[1], exp[2], exp[3], exp[4], exp[5], exp[6], exp[7], exp[8], exp[9], exp[10], exp[11], exp[12], exp[13], result, ctx.AntiTamperRegKey });

   injection_Inst.DeclaringType = ctx.CurrentModule.GlobalType;

   MethodDef cctor = ctx.CurrentModule.GlobalType.FindOrCreateStaticConstructor();

   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, injection_Inst));

   ProtectRuntime(injection_Inst, ctx);

   //ctx.analyzer.targetCtx.methods_virtualize.Add(injection_Inst); //If i want wirtualize that method
  }

  public void ProtectRuntime(MethodDef method, Context ctx)
  {
   //ctx.runtime_protect.runtime_refproxy.DeRefProxy(method, ctx);
   ctx.runtime_protect.runtime_intmath.DoIntMath(method, ctx);
   ctx.runtime_protect.runtime_controlflow2.DoControlFlow(method, ctx);
  }

  #region NotUsed

  //public int EnumNum(Context ctx)
  //{
  // int num = 0;

  // foreach (var t in ctx.analyzer.targetCtx.types_usercode)
  // {
  //  ctx.logger.Progress("Num for: " + t.Name);

  //  char[] chars = t.Name.ToString().ToCharArray();
  //  for (int a = 0; a < chars.Length; a++)
  //  {
  //   num += (int)chars[a];
  //  }
  // }

  // ctx.logger.Progress("Final num is:" +num);

  // return num;

  //}

  #endregion



 }
}
