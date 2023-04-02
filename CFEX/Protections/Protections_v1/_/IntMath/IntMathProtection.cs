using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet.Emit;
using dnlib.DotNet;

namespace Eddy_Protector.Protections.IntMath
{
 class IntMathProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Puts numbers into independently numbers oprations";
  public override string Id => Author + ".IntMath";
  public override string Name => "IntMath";

  public override void Execute(Context ctx)
  {

   foreach (var m in ctx.analyzer.targetCtx.methods_usercode)
   {
    ctx.logger.Progress(Id+" : "+"Processing method "+ m.Name);
    DoIntMath(m);
   }

  }

  public void DoIntMath(MethodDef method)
  {

   INTMHelper IMHelper = new INTMHelper();

   for (int i = 0; i < method.Body.Instructions.Count; i++)
   {
    Instruction instruction = method.Body.Instructions[i];
    if (instruction.Operand is int)
    {
     List<Instruction> instructions = IMHelper.Calc(Convert.ToInt32(instruction.Operand));
     instruction.OpCode = OpCodes.Nop;
     foreach (Instruction instr in instructions)
     {
      method.Body.Instructions.Insert(i + 1, instr);
      i++;
     }

    }
   }
  }
 }
 class RuntimeIntMathProtection
 {
  public void DoIntMath(MethodDef method,Context ctx)
  {
   ctx.logger.Progress("IntMath : " + "Processing method " + method.Name);
   var p =new IntMathProtection();
   p.DoIntMath(method);
  }
 }

}
