using System;
using System.Reflection;

namespace Eddy_Protector_Runtime
{
	internal static class CalliInj
	{
		public static IntPtr ResolveToken(int token)
		{
			Module module = typeof(CalliInj).Module;
			return module.ResolveMethod(token ^ Mutation.KeyI0).MethodHandle.GetFunctionPointer();
		}
	}
}
