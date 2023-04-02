using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Eddy_Protector_Protections.Protections.RefProxy
{
	public interface IRPEncoding
	{
		Instruction[] EmitDecode(MethodDef init, RPContext ctx, Instruction[] arg);
		int Encode(MethodDef init, RPContext ctx, int value);
	}
}
