using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Eddy_Protector.Protections.Constants
{
	[Flags]
	internal enum EncodeElements
	{
		Strings = 1,
		Numbers = 2,
		Primitive = 4,
		Initializers = 8
	}
}
