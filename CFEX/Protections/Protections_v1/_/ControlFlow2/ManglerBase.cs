using dnlib.DotNet.Emit;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Eddy_Protector.Protections.ControlFlow2
{
	internal abstract class ManglerBase
	{
		protected ManglerBase()
		{
		}
		protected static IEnumerable<InstrBlock> GetAllBlocks(ScopeBlock scope)
		{
			foreach (BlockBase iteratorVariable0 in scope.Children)
			{
				if (iteratorVariable0 is InstrBlock)
				{
					yield return (InstrBlock)iteratorVariable0;
				}
				else
				{
					foreach (InstrBlock iteratorVariable1 in GetAllBlocks((ScopeBlock)iteratorVariable0))
					{
						yield return iteratorVariable1;
					}
				}
			}
		}

		public abstract void Mangle(CilBody body, ScopeBlock root, CFContext ctx);

	}
}

