using Eddy_Protector.Virtualization.CFG;
using Eddy_Protector.Virtualization.RT;

namespace Eddy_Protector.Virtualization.AST.IL
{
	public class ILJumpTable : IILOperand, IHasOffset
	{
		public ILJumpTable(IBasicBlock[] targets)
		{
			Targets = targets;
			Chunk = new JumpTableChunk(this);
		}

		public JumpTableChunk Chunk
		{
			get;
		}

		public ILInstruction RelativeBase
		{
			get;
			set;
		}

		public IBasicBlock[] Targets
		{
			get;
			set;
		}

		public uint Offset => Chunk.Offset;

		public override string ToString()
		{
			return string.Format("[..{0}..]", Targets.Length);
		}
	}
}