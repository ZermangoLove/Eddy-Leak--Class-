using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;

namespace Eddy_Protector.Protections.ControlFlow2
{
	internal interface IPredicate
	{
		void EmitSwitchLoad(IList<Instruction> instrs);
		int GetSwitchKey(int key);
		void Init(CilBody body);
	}
}

