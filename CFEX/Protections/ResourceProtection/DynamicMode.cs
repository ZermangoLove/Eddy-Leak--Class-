﻿using Eddy_Protector_Ciphering.AST;
using Eddy_Protector_Ciphering.Generation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Protector.Protections.ResourcesProtect
{
 internal class DynamicMode : IEncodeMode
 {
  Action<uint[], uint[]> encryptFunc;

  public IEnumerable<Instruction> EmitDecrypt(MethodDef init, REContext ctx, Local block, Local key)
  {
   StatementBlock encrypt, decrypt;
   ctx.DynCipher.GenerateCipherPair(ctx.Random, out encrypt, out decrypt);
   var ret = new List<Instruction>();

   var codeGen = new CodeGen(block, key, init, ret);
   codeGen.GenerateCIL(decrypt);
   codeGen.Commit(init.Body);

   var dmCodeGen = new DMCodeGen(typeof(void), new[] {
    Tuple.Create("{BUFFER}", typeof(uint[])),
    Tuple.Create("{KEY}", typeof(uint[]))
   });
   dmCodeGen.GenerateCIL(encrypt);
   encryptFunc = dmCodeGen.Compile<Action<uint[], uint[]>>();

   return ret;
  }

  public uint[] Encrypt(uint[] data, int offset, uint[] key)
  {
   var ret = new uint[key.Length];
   Buffer.BlockCopy(data, offset * sizeof(uint), ret, 0, key.Length * sizeof(uint));
   encryptFunc(ret, key);
   return ret;
  }

  class CodeGen : CILCodeGen
  {
   readonly Local block;
   readonly Local key;

   public CodeGen(Local block, Local key, MethodDef init, IList<Instruction> instrs)
    : base(init, instrs)
   {
    this.block = block;
    this.key = key;
   }

   protected override Local Var(Variable var)
   {
    if (var.Name == "{BUFFER}")
     return block;
    if (var.Name == "{KEY}")
     return key;
    return base.Var(var);
   }
  }
 }
}
