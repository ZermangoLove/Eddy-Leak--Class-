using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Eddy_Protector.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Cypher;
using Confuser.DynCipher;

namespace Eddy_Protector.Protections.Constants
{
	internal class CEContext
	{
		public Context Context;
		public ConstantsProtection Protection;
		public ModuleDef Module;

		public FieldDef BufferField;
		public FieldDef DataField;
		public TypeDef DataType;
		public MethodDef InitMethod;

		public int DecoderCount;
		public List<Tuple<MethodDef, DecoderDesc>> Decoders;

		public EncodeElements Elements;
		public List<uint> EncodedBuffer;

		public Mode Mode;
		public IEncodeMode ModeHandler;

		public RandomGenerator Random;

		public IDynCipherService DynCipher;

		public TypeDef CfgCtxType;
		public MethodDef CfgCtxCtor;
		public MethodDef CfgCtxNext;
		public Dictionary<MethodDef, List<Tuple<Instruction, uint, IMethod>>> ReferenceRepl;

  public List<MethodDef> RuntimeMethods = new List<MethodDef>();

	}

	internal class DecoderDesc
	{
		public object Data;
		public byte InitializerID;
		public byte NumberID;
		public byte StringID;
	}
}
