using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Eddy_Protector.Protections.ControlFlow2
{

	internal class ScopeBlock : BlockBase
	{
		public ScopeBlock(BlockType type, ExceptionHandler handler) : base(type)
		{
			this.Handler = handler;
			this.Children = new List<BlockBase>();
		}

		public Instruction GetFirstInstr()
		{
			BlockBase base2 = this.Children.First<BlockBase>();
			if (base2 is ScopeBlock)
			{
				return ((ScopeBlock)base2).GetFirstInstr();
			}
			return ((InstrBlock)base2).Instructions.First<Instruction>();
		}

		public Instruction GetLastInstr()
		{
			BlockBase base2 = this.Children.Last<BlockBase>();
			if (base2 is ScopeBlock)
			{
				return ((ScopeBlock)base2).GetLastInstr();
			}
			return ((InstrBlock)base2).Instructions.Last<Instruction>();
		}

		public override void ToBody(CilBody body)
		{
			if (base.Type != BlockType.Normal)
			{
				if (base.Type == BlockType.Try)
				{
					this.Handler.TryStart = this.GetFirstInstr();
					this.Handler.TryEnd = this.GetLastInstr();
				}
				else if (base.Type == BlockType.Filter)
				{
					this.Handler.FilterStart = this.GetFirstInstr();
				}
				else
				{
					this.Handler.HandlerStart = this.GetFirstInstr();
					this.Handler.HandlerEnd = this.GetLastInstr();
				}
			}
			foreach (BlockBase base2 in this.Children)
			{
				base2.ToBody(body);
			}
		}

		public override string ToString()
		{
			StringBuilder builder = new StringBuilder();
			if (base.Type == BlockType.Try)
			{
				builder.Append("try ");
			}
			else if (base.Type == BlockType.Handler)
			{
				builder.Append("handler ");
			}
			else if (base.Type == BlockType.Finally)
			{
				builder.Append("finally ");
			}
			else if (base.Type == BlockType.Fault)
			{
				builder.Append("fault ");
			}
			builder.AppendLine("{");
			foreach (BlockBase base2 in this.Children)
			{
				builder.Append(base2);
			}
			builder.AppendLine("}");
			return builder.ToString();
		}

		public List<BlockBase> Children { get; set; }

		public ExceptionHandler Handler { get; private set; }
	}
}

