using System;
using System.Collections.Generic;


namespace Eddy_Protector.Virtualization.AST.IR
{
	public class IRInstrList : List<IRInstruction>
	{
		public override string ToString()
		{
			return string.Join(Environment.NewLine, this);
		}

		public void VisitInstrs<T>(VisitFunc<IRInstrList, IRInstruction, T> visitFunc, T arg)
		{
			for (var i = 0; i < Count; i++)
				visitFunc(this, this[i], ref i, arg);
		}
	}
}