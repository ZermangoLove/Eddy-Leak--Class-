using dnlib.DotNet.Emit;
using Eddy_Protector_Core.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Eddy_Protector_Protections.Protections.Mutation
{
	class MutateStageProcessor
	{
		private IList<Instruction> instructions;
		private int i;
		/// <summary>
		/// 
		/// </summary>
		/// <param name="body">Body of current method</param>
		/// <param name="i">Index of body</param>
		public MutateStageProcessor(IList<Instruction> instructions, int i)
		{
			operand = instructions[i].GetLdcI4Value();
			this.instructions = instructions;
			this.i = i;
		}

		/// <summary>
		/// Start operand, which will be modified after each loop
		/// </summary>
		private int operand = 0;

		/// <summary>
		/// Key for the arithmetic operations
		/// </summary>
		int key = new int();

		public void Mutate(ref int forward)
		{
			for (int i = 0; i < new Random().Next(3, 7); i++)
			{
				//1/10 for sizeof
				key = (new Random().Next(0, 12) == 0) ? Utils.GetSizeofValue() : new Random().Next(0, 4000);
				operand = instructions[this.i].GetLdcI4Value();
				switch (new Random().Next(0, 3))
				{
					case 0: AddMutation(); break;
					case 1: SubMutation(); break;
					case 2: XorMutation(); break;
				}
				forward += 2;
			}
		}

		#region Mutations
		private void AddMutation()
		{
			instructions[i] = Instruction.CreateLdcI4(operand + key);
			DnlibUtils.InsertInstructions(instructions,
			new Dictionary<Instruction, int>()
			{
																{ Instruction.CreateLdcI4(key), i + 1},
																{ OpCodes.Sub.ToInstruction(), i + 2},
				//{ OpCodes.Nop.ToInstruction(), i+ 3 },
			}
			);

		}

		private void SubMutation()
		{
			instructions[i] = Instruction.CreateLdcI4(operand - key);
			DnlibUtils.InsertInstructions(instructions,
			new Dictionary<Instruction, int>()
			{
																{ Instruction.CreateLdcI4(key), i + 1},
																{ OpCodes.Add.ToInstruction(), i + 2},
				//{ OpCodes.Nop.ToInstruction(), i+ 3 },
			}
			);

		}

		private void XorMutation()
		{
			instructions[i] = Instruction.CreateLdcI4(operand ^ key);
			DnlibUtils.InsertInstructions(instructions,
			new Dictionary<Instruction, int>()
			{
																{ Instruction.CreateLdcI4(key), i + 1},
																{ OpCodes.Xor.ToInstruction(), i + 2},
				//{ OpCodes.Nop.ToInstruction(), i+ 3 },
			}
			);
		}
		#endregion
	}
}
