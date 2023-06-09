﻿using Eddy_Protector.Virtualization.CFG;

namespace Eddy_Protector.Virtualization.AST.IR
{
	public class IRJumpTable : IIROperand
	{
		public IRJumpTable(IBasicBlock[] targets)
		{
			Targets = targets;
		}

		public IBasicBlock[] Targets
		{
			get;
			set;
		}

		public ASTType Type => ASTType.Ptr;

		public override string ToString()
		{
			return string.Format("[..{0}..]", Targets.Length);
		}
	}
}