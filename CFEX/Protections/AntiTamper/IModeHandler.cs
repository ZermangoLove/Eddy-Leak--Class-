using System;
using System.Collections.Generic;

using dnlib.DotNet;
using Protector.Protections;

namespace Protector.Protections.AntiTamper
{
	internal interface IModeHandler
	{
		ModuleDef HandleInject(ModuleDef module, ProtectorContext context);
		void HandleMD(List<MethodDef> methods, ProtectorContext context);
	}
}