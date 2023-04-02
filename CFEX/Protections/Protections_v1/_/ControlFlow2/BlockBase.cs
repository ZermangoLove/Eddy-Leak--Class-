using dnlib.DotNet.Emit;
using System;
using System.Runtime.CompilerServices;

namespace Eddy_Protector.Protections.ControlFlow2
{
	internal abstract class BlockBase
	{
		public BlockBase(BlockType type)
		{
			this.Type = type;
		}

		public abstract void ToBody(CilBody body);

		public ScopeBlock Parent { get; private set; }

		public BlockType Type { get; private set; }
	}
}

