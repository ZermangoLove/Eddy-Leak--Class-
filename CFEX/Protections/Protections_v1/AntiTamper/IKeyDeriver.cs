using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Eddy_Protector_Core.Core;
using Eddy_Protector_Ciphering;

namespace Eddy_Protector_Protections.Protections.AntiTamper
{
	internal enum Mode
	{
		Normal,
		Dynamic
	}

	internal interface IKeyDeriver
	{
		void Init(Context ctx, RandomGenerator random);
		uint[] DeriveKey(uint[] a, uint[] b);
		IEnumerable<Instruction> EmitDerivation(MethodDef method, Context ctx, Local dst, Local src);
	}
}