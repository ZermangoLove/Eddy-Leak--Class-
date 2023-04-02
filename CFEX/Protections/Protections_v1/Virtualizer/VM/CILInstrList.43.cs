using System;
using System.Collections.Generic;
using dnlib.DotNet.Emit;

namespace Eddy_Protector.Virtualization.CFG
{
	public class CILInstrList : List<Instruction>
	{
		public override string ToString()
		{
			return string.Join(Environment.NewLine, this);
		}
	}
}