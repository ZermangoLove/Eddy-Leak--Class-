using System;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using System.Collections.Generic;

namespace Eddy_Protector_Protections.Protections.AntiTamper
{
	internal interface IModeHandler
	{
		void HandleInject(Context context);
		void HandleMD(List<MethodDef> methods,Context context);
	}
}