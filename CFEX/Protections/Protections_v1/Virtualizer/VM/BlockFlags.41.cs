using System;

namespace Eddy_Protector.Virtualization.CFG
{
	[Flags]
	public enum BlockFlags
	{
		Normal = 0,
		ExitEHLeave = 1,
		ExitEHReturn = 2
	}
}