using Eddy_Protector.Virtualization.RT;

namespace Eddy_Protector.Virtualization.AST.IR
{
	public class IRDataTarget : IIROperand
	{
		public IRDataTarget(BinaryChunk target)
		{
			Target = target;
		}

		public BinaryChunk Target
		{
			get;
			set;
		}

		public string Name
		{
			get;
			set;
		}

		public ASTType Type => ASTType.Ptr;

		public override string ToString()
		{
			return Name;
		}
	}
}