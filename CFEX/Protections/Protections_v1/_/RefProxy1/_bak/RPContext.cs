using dnlib.DotNet;
using System.Collections.Generic;
using Eddy_Protector.Core;
using dnlib.DotNet.Emit;
using Confuser.DynCipher;

namespace Eddy_Protector.Protections.RefProxy
{
	internal enum Mode
	{
		Mild,
		Strong,
		Ftn
	}

	internal enum EncodingType
	{
		Normal,
		Expression,
		x86
	}


	internal class RPContext
	{
		public RefProxyProtection Protection;
		public CilBody Body;
		public HashSet<Instruction> BranchTargets;
		public Context ctx;
		public Dictionary<MethodSig, TypeDef> Delegates;
		public int Depth;
		public IDynCipherService DynCipher;
		public EncodingType Encoding;
		public IRPEncoding EncodingHandler;
		public int InitCount;
		public bool InternalAlso;
		public MethodDef Method;
		public Mode Mode;

		public RPMode ModeHandler;
		public ModuleDef Module;
		public Confuser.DynCipher.RandomGenerator Random;
		public bool TypeErasure;

		public List<MethodDef> RuntimeMethods;
		public List<CAArgument> CCargs;

	}
}
