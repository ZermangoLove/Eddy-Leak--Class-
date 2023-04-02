using Eddy_Protector.Virtualization.AST.IR;
using Eddy_Protector.Virtualization.VMIR;


namespace Eddy_Protector.Virtualization.VMIL
{
	public interface ITranslationHandler
	{
		IROpCode IRCode
		{
			get;
		}

		void Translate(IRInstruction instr, ILTranslator tr);
	}
}