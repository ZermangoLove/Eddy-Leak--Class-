using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Protector.Protections.ControlFlow
{
 class RTControlFlow1
 {
  ControlFlow1 control;
  public RTControlFlow1(ModuleDef mod)
  {
   control = new ControlFlow1(mod);
  }
  public void AddControlFlow(MethodDef method, ProtectorContext context)
  {
   control.DoControlFlow(method, context);
  }
 }

 class ControlFlow1
 {
  ModuleDef module;
  public ControlFlow1(ModuleDef mod)
  {
   module = mod;
  }
  public void DoControlFlow(MethodDef method, ProtectorContext ctx)
  {
   var cFHelper = new CFHelper();
   cFHelper.ctx = ctx;

   var dnlib_utils = new DnlibUtils();

   if (method.HasBody && method.Body.Instructions.Count > 0 && !method.IsConstructor)
   {
    if (true/*!cFHelper.HasUnsafeInstructions(method)*/)
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

         Local local = new Local(module.CorLibTypes.UInt64);
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

 class Blocks
 {
  public List<Block> blocks = new List<Block>();
  public Block getBlock(int id)
  {
   return blocks.Single(block => block.ID == id);
  }

  public void Scramble(out Blocks incGroups)
  {
   var Random = new Random();
   Blocks groups = new Blocks();
   foreach (var group in blocks)
    groups.blocks.Insert(Random.Next(groups.blocks.Count), group);
   incGroups = groups;
  }
 }

 class Block
 {
  public int ID = 0;
  public int nextBlock = 0;
  public List<Instruction> instructions = new List<Instruction>();
 }

 class CFHelper
 {
  static Random rnd = new Random();
  public ProtectorContext ctx;

  public bool HasUnsafeInstructions(MethodDef methodDef)
  {
   if (methodDef.HasBody)
   {
    if (methodDef.Body.HasVariables)
     return methodDef.Body.Variables.Any(x => x.Type.IsPointer);
   }
   return false;
  }
  public Blocks GetBlocks(MethodDef method)
  {
   Blocks blocks = new Blocks();
   Block block = new Block();
   int Id = 0;
   int usage = 0;
   foreach (Instruction instruction in method.Body.Instructions)
   {
    int pops = 0;
    int stacks;
    instruction.CalculateStackUsage(out stacks, out pops);
    block.instructions.Add(instruction);
    usage += stacks - pops;
    if (stacks == 0)
    {
     if (instruction.OpCode != OpCodes.Nop)
     {
      if (usage == 0 || instruction.OpCode == OpCodes.Ret)
      {

       block.ID = Id;
       Id++;
       block.nextBlock = block.ID + 1;
       blocks.blocks.Add(block);
       block = new Block();
      }
     }
    }
   }
   return blocks;
  }
  public List<Instruction> Calc(int value)
  {
   List<Instruction> instructions = new List<Instruction>();

   uint num = ctx.random_generator.RandomUint();

   bool once = Convert.ToBoolean(new Random().Next(2));

   uint num1 = ctx.random_generator.RandomUint();

   long initial = value - num + (once ? (0 - num1) : num1);

   instructions.Add(Instruction.Create(OpCodes.Ldc_I8, initial));
   instructions.Add(Instruction.Create(OpCodes.Ldc_I8, num));
   instructions.Add(Instruction.Create(OpCodes.Add));
   instructions.Add(Instruction.Create(OpCodes.Ldc_I8, num1));
   instructions.Add(Instruction.Create(once ? OpCodes.Add : OpCodes.Sub));
   return instructions;

  }
 }

 class DnlibUtils
 {
  public bool hasExceptionHandlers(MethodDef methodDef)
  {
   if (methodDef.Body.HasExceptionHandlers)
    return true;
   return false;
  }

  public bool Optimize(MethodDef methodDef)
  {
   if (methodDef.Body == null)
    return false;
   methodDef.Body.OptimizeMacros();
   methodDef.Body.OptimizeBranches();
   return true;
  }

  public bool Simplify(MethodDef methodDef)
  {
   if (methodDef.Parameters == null)
    return false;
   methodDef.Body.SimplifyMacros(methodDef.Parameters);
   return true;
  }

 }


}
