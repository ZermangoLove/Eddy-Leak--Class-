using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Eddy_Protector_Protections.Protections.ControlFlow2
{
	internal class InstrBlock : BlockBase
	{
		public InstrBlock() : base(BlockType.Normal)
		{
			this.Instructions = new List<Instruction>();
		}

		public override void ToBody(CilBody body)
		{
			foreach (Instruction instruction in this.Instructions)
			{
				body.Instructions.Add(instruction);
			}
		}

		public override string ToString()
		{
			StringBuilder builder = new StringBuilder();
			foreach (Instruction instruction in this.Instructions)
			{
				builder.AppendLine(instruction.ToString());
			}
			return builder.ToString();
		}

		public List<Instruction> Instructions { get; set; }
	}
}

