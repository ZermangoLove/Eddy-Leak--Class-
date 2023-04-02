namespace Eddy_Protector.Virtualization.VMIR
{
	public interface ITransform
	{
		void Initialize(IRTransformer tr);
		void Transform(IRTransformer tr);
	}
}