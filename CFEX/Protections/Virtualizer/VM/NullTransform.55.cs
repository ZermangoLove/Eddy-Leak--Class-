using dnlib.DotNet.Emit;
using Eddy_Protector.Virtualization.AST.ILAST;


namespace Eddy_Protector.Virtualization.ILAST.Transformation
{
    public class NullTransform : ITransformationHandler
    {
        public void Initialize(ILASTTransformer tr)
        {
        }

        public void Transform(ILASTTransformer tr)
        {
            tr.Tree.TraverseTree(Transform, tr);
        }

        private static void Transform(ILASTExpression expr, ILASTTransformer tr)
        {
            if(expr.ILCode != Code.Ldnull)
                return;

            expr.ILCode = Code.Ldc_I4;
            expr.Operand = 0;
        }
    }
}