/* Codded by: Eddy^CZ 2018 
   Date: 15.12.2018
 */

using System;
using System.Collections.Generic;
using Eddy_Protector_Ciphering;
using Eddy_Protector_Ciphering.AST;
using Eddy_Protector_Ciphering.Generation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Eddy_Protector_Core.Core;

namespace Eddy_Protector_Protections.Protections.AntiTamper
{
	internal class DynamicDeriver : IKeyDeriver
	{
		StatementBlock derivation;
		Action<uint[], uint[]> encryptFunc;

		public void Init(Context ctx, RandomGenerator random)
		{
			StatementBlock dummy;
			new DynCipherService().GenerateCipherPair(random, out derivation, out dummy);
			var dmCodeGen = new DMCodeGen(typeof(void), new[] {
				Tuple.Create("{BUFFER}", typeof(uint[])),
				Tuple.Create("{KEY}", typeof(uint[]))
			});
			dmCodeGen.GenerateCIL(derivation);
			encryptFunc = dmCodeGen.Compile<Action<uint[], uint[]>>();
		}

		public uint[] DeriveKey(uint[] a, uint[] b)
		{
			var ret = new uint[0x10];
			Buffer.BlockCopy(a, 0, ret, 0, a.Length * sizeof(uint));
			encryptFunc(ret, b);
			return ret;
		}

		public IEnumerable<Instruction> EmitDerivation(MethodDef method, Context ctx, Local dst, Local src)
		{
			var ret = new List<Instruction>();
			var codeGen = new CodeGen(dst, src, method, ret);
			codeGen.GenerateCIL(derivation);
			codeGen.Commit(method.Body);
			return ret;
		}

		class CodeGen : CILCodeGen
		{
			readonly Local block;
			readonly Local key;

			public CodeGen(Local block, Local key, MethodDef method, IList<Instruction> instrs)
				: base(method, instrs)
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