using dnlib.DotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Eddy_Protector.Virtualization
{
	public interface IVMSettings
	{
		int Seed
		{
			get;
		}

		bool IsDebug
		{
			get;
		}

		bool ExportDbgInfo
		{
			get;
		}

		bool DoStackWalk
		{
			get;
		}

		bool IsVirtualized(MethodDef method);
		bool IsExported(MethodDef method);
	}
}
