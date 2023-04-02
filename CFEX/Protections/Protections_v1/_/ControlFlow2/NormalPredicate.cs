using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;

namespace Eddy_Protector.Protections.ControlFlow2
{
	internal class NormalPredicate : IPredicate
	{
		private readonly CFContext ctx;
		private bool inited;
		private int xorKey;

		public NormalPredicate(CFContext ctx)
		{
			this.ctx = ctx;
		}

		public void EmitSwitchLoad(IList<Instruction> instrs)
		{
			instrs.Add(Instruction.Create(OpCodes.Ldc_I4, this.xorKey));
			instrs.Add(Instruction.Create(OpCodes.Xor));
		}

		public int GetSwitchKey(int key) =>
						(key ^ this.xorKey);

		public void Init(CilBody body)
		{
			if (!this.inited)
			{
				this.xorKey = this.ctx.Random.NextInt32();
				this.inited = true;
			}
		}
	}
}

