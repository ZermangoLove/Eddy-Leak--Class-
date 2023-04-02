namespace Eddy_Protector.Protections.ControlFlow2
{
	using Confuser.DynCipher;
	using Confuser.DynCipher.AST;
	using Confuser.DynCipher.Generation;
	using Core;
	using dnlib.DotNet;
	using dnlib.DotNet.Emit;
	using dnlib.DotNet.Writer;
	using System;
	using System.Collections.Generic;

	internal class x86Predicate : IPredicate
	{
		private readonly CFContext ctx;
		private x86Encoding encoding;
		private static readonly object Encoding = new object();
		private bool inited;

		public x86Predicate(CFContext ctx)
		{
			this.ctx = ctx;
		}

		public void EmitSwitchLoad(IList<Instruction> instrs)
		{
			instrs.Add(Instruction.Create(OpCodes.Call, (IMethod)this.encoding.native));
		}

		public int GetSwitchKey(int key) =>
						this.encoding.expCompiled(key);

		public void Init(CilBody body)
		{
			if (!this.inited)
			{
				if (this.encoding == null)
				{
					this.encoding = new x86Encoding();
					this.encoding.Compile(this.ctx);
				}
				this.inited = true;
			}
		}

		private class x86Encoding
		{
			private byte[] code;
			private dnlib.DotNet.Writer.MethodBody codeChunk;
			public Func<int, int> expCompiled;
			private Expression expression;
			private Expression inverse;
			public MethodDef native;

			public void Compile(CFContext ctx)
			{
				x86Register? nullable;
				Variable variable = new Variable("{VAR}");
				Variable variable2 = new Variable("{RESULT}");
				CorLibTypeSig retType = ctx.context.CurrentModule.CorLibTypes.Int32;
				this.native = new MethodDefUser(ctx.context.generator.GenerateNewName(), MethodSig.CreateStatic(retType, retType), MethodAttributes.CompilerControlled | MethodAttributes.PinvokeImpl | MethodAttributes.Static);
				this.native.ImplAttributes = MethodImplAttributes.IL | MethodImplAttributes.ManagedMask | MethodImplAttributes.Native | MethodImplAttributes.PreserveSig;
				ctx.context.CurrentModule.GlobalType.Methods.Add(this.native);
				x86CodeGen codeGen = new x86CodeGen();
				do
				{
					VariableExpression var = new VariableExpression
					{
						Variable = variable
					};
					VariableExpression result = new VariableExpression
					{
						Variable = variable2
					};
					ctx.DynCipher.GenerateExpressionPair(ctx.Random, var, result, ctx.Depth, out this.expression, out this.inverse);
					nullable = codeGen.GenerateX86(this.inverse, (v, r) => new x86Instruction[] { x86Instruction.Create(x86OpCode.POP, new Ix86Operand[] { new x86RegisterOperand(r) }) });
				}
				while (!nullable.HasValue);
				this.code = CodeGenUtils.AssembleCode(codeGen, nullable.Value);
				this.expCompiled = new DMCodeGen(typeof(int), new Tuple<string, Type>[] { Tuple.Create<string, Type>("{VAR}", typeof(int)) }).GenerateCIL(this.expression).Compile<Func<int, int>>();
				ctx.context.CurrentModuleWriterListener.OnWriterEvent += new EventHandler<ModuleWriterListenerEventArgs>(this.InjectNativeCode);
			}

			private void InjectNativeCode(object sender, ModuleWriterListenerEventArgs e)
			{
				ModuleWriterBase base2 = (ModuleWriterBase)sender;
				if (e.WriterEvent == ModuleWriterEvent.MDEndWriteMethodBodies)
				{
					this.codeChunk = base2.MethodBodies.Add(new dnlib.DotNet.Writer.MethodBody(this.code));
				}
				else if (e.WriterEvent == ModuleWriterEvent.EndCalculateRvasAndFileOffsets)
				{
					uint rid = base2.MetaData.GetRid(this.native);
					base2.MetaData.TablesHeap.MethodTable[rid].RVA = (uint)this.codeChunk.RVA;
				}
			}
		}
	}
}

