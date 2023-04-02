using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Eddy_Protector.Core;
using Confuser.DynCipher;

namespace Eddy_Protector.Protections.AntiTamper
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