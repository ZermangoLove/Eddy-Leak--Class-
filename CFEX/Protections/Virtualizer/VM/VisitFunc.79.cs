using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Eddy_Protector.Virtualization
{
		public delegate void VisitFunc<TList, TInstr, TState>(TList list, TInstr instr, ref int index, TState state);
}
