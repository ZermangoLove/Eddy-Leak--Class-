namespace Eddy_Protector.Virtualization.VMIL
{
	public interface IPostTransform
	{
		void Initialize(ILPostTransformer tr);
		void Transform(ILPostTransformer tr);
	}
}