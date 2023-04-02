using dnlib.DotNet;
using Eddy_Protector.Virtualization.CFG;
using Eddy_Protector.Virtualization.RT;

namespace Eddy_Protector.Virtualization.AST.IL
{
	public class ILBlock : BasicBlock<ILInstrList>
	{
		public ILBlock(int id, ILInstrList content)
						: base(id, content)
		{
		}

		public virtual IKoiChunk CreateChunk(VMRuntime rt, MethodDef method)
		{
			return new BasicBlockChunk(rt, method, this);
		}
	}
}