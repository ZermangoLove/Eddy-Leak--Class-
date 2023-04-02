using Confuser.DynCipher;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using Eddy_Protector.Core;

namespace Eddy_Protector.Protections.ControlFlow2
{
	internal class CFContext
	{
		public Context context;
		public int Depth;
		public IDynCipherService DynCipher;
		public double Intensity;
		public bool JunkCode;
		public MethodDef Method;
		public PredicateType Predicate;
		public RandomGenerator Random;
		public CFType Type;

		public void AddJump(IList<Instruction> instrs, Instruction target)
		{
			if (((!this.context.CurrentModule.IsClr40 && this.JunkCode) && (!this.Method.DeclaringType.HasGenericParameters && !this.Method.HasGenericParameters)) && ((instrs[0].OpCode.FlowControl == FlowControl.Call) || (instrs[0].OpCode.FlowControl == FlowControl.Next)))
			{
				switch (this.Random.NextInt32(3))
				{
					case 0:
						instrs.Add(Instruction.Create(OpCodes.Ldc_I4_0));
						instrs.Add(Instruction.Create(OpCodes.Brtrue, instrs[0]));
						break;

					case 1:
						instrs.Add(Instruction.Create(OpCodes.Ldc_I4_1));
						instrs.Add(Instruction.Create(OpCodes.Brfalse, instrs[0]));
						break;

					case 2:
						{
							bool flag = false;
							if (this.Random.NextBoolean())
							{
								TypeDef def = this.Method.Module.Types[this.Random.NextInt32(this.Method.Module.Types.Count)];
								if (def.HasMethods)
								{
									instrs.Add(Instruction.Create(OpCodes.Ldtoken, def.Methods[this.Random.NextInt32(def.Methods.Count)]));
									instrs.Add(Instruction.Create(OpCodes.Box, (ITypeDefOrRef)this.Method.Module.CorLibTypes.GetTypeRef("System", "RuntimeMethodHandle")));
									flag = true;
								}
							}
							if (!flag)
							{
								instrs.Add(Instruction.Create(OpCodes.Ldc_I4, this.Random.NextBoolean() ? 0 : 1));
								instrs.Add(Instruction.Create(OpCodes.Box, this.Method.Module.CorLibTypes.Int32.TypeDefOrRef));
							}
							Instruction item = Instruction.Create(OpCodes.Pop);
							instrs.Add(Instruction.Create(OpCodes.Brfalse, instrs[0]));
							instrs.Add(Instruction.Create(OpCodes.Ldc_I4, this.Random.NextBoolean() ? 0 : 1));
							instrs.Add(item);
							break;
						}
				}
			}
			instrs.Add(Instruction.Create(OpCodes.Br, target));
		}

		public void AddJunk(IList<Instruction> instrs)
		{
			if (!this.context.CurrentModule.IsClr40 && this.JunkCode)
			{
				switch (this.Random.NextInt32(6))
				{
					case 0:
						instrs.Add(Instruction.Create(OpCodes.Pop));
						return;

					case 1:
						instrs.Add(Instruction.Create(OpCodes.Dup));
						return;

					case 2:
						instrs.Add(Instruction.Create(OpCodes.Throw));
						return;

					case 3:
						instrs.Add(Instruction.Create(OpCodes.Ldarg, new Parameter(0xff)));
						return;

					case 4:
						{
							Local local = new Local(null)
							{
								Index = 0xff
							};
							instrs.Add(Instruction.Create(OpCodes.Ldloc, local));
							return;
						}
					case 5:
						instrs.Add(Instruction.Create(OpCodes.Ldtoken, (IMethod)this.Method));
						return;
				}
			}
		}
	}
}

