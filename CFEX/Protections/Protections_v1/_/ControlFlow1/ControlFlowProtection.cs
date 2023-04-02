using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Eddy_Protector.Protections.ControlFlow1
{
 class ControlFlowProtection1 : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Provide control flow for methods based on Panda obfuscator";
  public override string Id => Author + ".ControlFlow";
  public override string Name => "Control flow panda";

  public override void Execute(Context ctx)
  {
   var protection = new RuntimeControlFlowProtection1();
   foreach (MethodDef method in ctx.analyzer.targetCtx.methods_usercode)
   {
    ctx.logger.Progress(String.Format("Control flow on method:  {0}", method.Name));

    for (int a = 0; a < 1; a++)
    {
     protection.DoControlFlow(method, ctx);
    }

   }
  }
 }

 class RuntimeControlFlowProtection1
 {
  public void DoControlFlow(MethodDef method, Context ctx)
  {
   var cFHelper = new CFHelper();
   cFHelper.ctx = ctx;
   

   var dnlib_utils = new DnlibUtils();

   if (method.HasBody && method.Body.Instructions.Count > 0  && !method.IsConstructor)
   {
    if (!cFHelper.HasUnsafeInstructions(method))
    {
     if (!dnlib_utils.hasExceptionHandlers(method))
     {
      if (dnlib_utils.Simplify(method))
      {
       Blocks blocks = cFHelper.GetBlocks(method);
       if (blocks.blocks.Count != 1)
       {

        blocks.Scramble(out blocks);

        for (int f = 0; f < 1; f++)
        {
         method.Body.Instructions.Clear();

         Local local = new Local(ctx.CurrentModule.CorLibTypes.UInt64);
         method.Body.Variables.Add(local);

         Instruction target = Instruction.Create(OpCodes.Nop);
         Instruction instr = Instruction.Create(OpCodes.Br, target);

         foreach (Instruction instruction in cFHelper.Calc(0))
         {
          method.Body.Instructions.Add(instruction);
         }

         method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, local));
         method.Body.Instructions.Add(Instruction.Create(OpCodes.Br, instr));
         method.Body.Instructions.Add(target);

         foreach (Block block in blocks.blocks)
         {
          if (block != blocks.getBlock((blocks.blocks.Count - 1)))
          {
           method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, local));
           foreach (Instruction instruction in cFHelper.Calc(block.ID))
           {
            method.Body.Instructions.Add(instruction);
           }

           method.Body.Instructions.Add(Instruction.Create(OpCodes.Ceq));
           Instruction instruction4 = Instruction.Create(OpCodes.Nop);
           method.Body.Instructions.Add(Instruction.Create(OpCodes.Brfalse, instruction4));

           foreach (Instruction instruction in block.instructions)
           {
            method.Body.Instructions.Add(instruction);
           }

           foreach (Instruction instruction in cFHelper.Calc(block.nextBlock))
           {
            method.Body.Instructions.Add(instruction);
           }

           method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, local));
           method.Body.Instructions.Add(instruction4);

          }
         }

         method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, local));

         foreach (Instruction instruction in cFHelper.Calc(blocks.blocks.Count - 1))
         {
          method.Body.Instructions.Add(instruction);
         }

         method.Body.Instructions.Add(Instruction.Create(OpCodes.Ceq));
         method.Body.Instructions.Add(Instruction.Create(OpCodes.Brfalse, instr));
         method.Body.Instructions.Add(Instruction.Create(OpCodes.Br, blocks.getBlock((blocks.blocks.Count - 1)).instructions[0]));
         method.Body.Instructions.Add(instr);

         foreach (Instruction lastBlock in blocks.getBlock((blocks.blocks.Count - 1)).instructions)
         {
          method.Body.Instructions.Add(lastBlock);
         }

        }
       }
       dnlib_utils.Optimize(method);
      }
     }
    }
   }
  }
 }
}
