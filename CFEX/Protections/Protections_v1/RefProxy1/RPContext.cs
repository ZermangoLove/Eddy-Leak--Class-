using dnlib.DotNet;
using System.Collections.Generic;
using Eddy_Protector_Core.Core;
using dnlib.DotNet.Emit;
using Eddy_Protector_Ciphering;

namespace Eddy_Protector_Protections.Protections.RefProxy
{
	public enum Mode
	{
		Mild,
		Strong,
		Ftn
	}

	public enum EncodingType
	{
		Normal,
		Expression,
		x86
	}


	public class RPContext
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
		public RandomGenerator Random;
		public bool TypeErasure;

		public List<MethodDef> RuntimeMethods;
		public List<CAArgument> CCargs;

	}
}
