namespace Eddy_Protector.Virtualization.AST
{
	public abstract class ASTExpression : ASTNode
	{
		public ASTType? Type
		{
			get;
			set;
		}
	}
}