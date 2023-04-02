namespace Eddy_Protector.Virtualization.VMIL
{
	public interface ITransform
	{
		void Initialize(ILTransformer tr);
		void Transform(ILTransformer tr);
	}
}