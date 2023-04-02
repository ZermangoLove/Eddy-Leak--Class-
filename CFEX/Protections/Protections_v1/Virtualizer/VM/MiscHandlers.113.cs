using Eddy_Protector.Virtualization.AST.IL;
using Eddy_Protector.Virtualization.AST.IR;
using Eddy_Protector.Virtualization.VMIR;

namespace Eddy_Protector.Virtualization.VMIL.Translation
{
	public class VcallHandler : ITranslationHandler
	{
		public IROpCode IRCode => IROpCode.VCALL;

		public void Translate(IRInstruction instr, ILTranslator tr)
		{
			if (instr.Operand2 != null)
				tr.PushOperand(instr.Operand2);
			tr.PushOperand(instr.Operand1);
			tr.Instructions.Add(new ILInstruction(ILOpCode.VCALL));
		}
	}

	public class NopHandler : ITranslationHandler
	{
		public IROpCode IRCode => IROpCode.NOP;

		public void Translate(IRInstruction instr, ILTranslator tr)
		{
			tr.Instructions.Add(new ILInstruction(ILOpCode.NOP));
		}
	}
}