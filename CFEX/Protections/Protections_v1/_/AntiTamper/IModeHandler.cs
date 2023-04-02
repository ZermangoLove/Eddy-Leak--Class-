using System;
using Eddy_Protector.Core;
using dnlib.DotNet;
using System.Collections.Generic;

namespace Eddy_Protector.Protections.AntiTamper
{
	internal interface IModeHandler
	{
		void HandleInject(Context context);
		void HandleMD(List<MethodDef> methods,Context context);
	}
}