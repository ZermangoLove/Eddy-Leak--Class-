namespace Eddy_Protector.Virtualization.ILAST
{
	public interface ITransformationHandler
	{
		void Initialize(ILASTTransformer tr);
		void Transform(ILASTTransformer tr);
	}
}