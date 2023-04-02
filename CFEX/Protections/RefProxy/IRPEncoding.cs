using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Protector.Protections.RefProxy
{
	interface IRPEncoding
	{
		Instruction[] EmitDecode(MethodDef init, RPContext ctx, Instruction[] arg);
		int Encode(MethodDef init, RPContext ctx, int value);
	}
}
