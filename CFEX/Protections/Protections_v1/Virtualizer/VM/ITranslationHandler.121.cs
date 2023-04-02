using dnlib.DotNet.Emit;

//
using Eddy_Protector.Virtualization.AST.ILAST;
using Eddy_Protector.Virtualization.AST.IR;


namespace Eddy_Protector.Virtualization.VMIR
{
	public interface ITranslationHandler
	{
		Code ILCode
		{
			get;
		}

		IIROperand Translate(ILASTExpression expr, IRTranslator tr);
	}
}