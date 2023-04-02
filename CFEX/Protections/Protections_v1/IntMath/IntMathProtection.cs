using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet.Emit;
using dnlib.DotNet;

namespace Eddy_Protector_Protections.Protections.IntMath
{
 public class IntMathProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Puts numbers into independently numbers oprations";
  public override string Id => Author + ".IntMath";
  public override string Name => "IntMath";

  public override void Execute(Context ctx)
  {

   foreach (var m in ctx.analyzer.targetCtx.methods_usercode)
   {
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
 public class RuntimeIntMathProtection
 {
  public void DoIntMath(MethodDef method,Context ctx)
  {
   var p =new IntMathProtection();
   p.DoIntMath(method);
  }
 }

}
