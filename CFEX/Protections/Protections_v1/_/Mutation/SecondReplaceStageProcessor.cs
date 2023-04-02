using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Eddy_Protector.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Eddy_Protector.Protections.Mutation
{
	class SecondReplaceStageProcessor
	{
		private ModuleDef module;
		CilBody body;
		private IList<Instruction> instructions;
		private int operand;
		private int i;
		private Importer importer;

		public SecondReplaceStageProcessor(ModuleDef module, CilBody body, int i)
		{
			this.module = module;
			this.body = body;
			this.instructions = body.Instructions;
			operand = instructions[i].GetLdcI4Value();
			this.i = i;
			this.importer = new Importer(module);
		}

		public void Replace(ref int forward)
		{
			int bbc = 0;
			int cunt = 0;


			if (Utils.IsSizeof(operand))
				sizeofReplacer();
			else if (operand == 0)
				emptyTypes();

			else
			{
				switch (new Random().Next(0, 4))
				{
					case 0: floorReplacer(); forward += 2; break;
					case 1: sqrtReplacer(ref bbc); break;
					case 2: roundReplacer(); forward += 2; break;
					//case 3: structReplacer(ref cunt); break;
					case 3: localReplacer(); forward += 0; break;
				}
			}

			forward += bbc + cunt;


		}

		private void floorReplacer()
		{
			instructions[i] = OpCodes.Ldc_R8.ToInstruction(operand + RandomNumberBetween(0.01, 0.99));
			DnlibUtils.InsertInstructions(instructions,
			new Dictionary<Instruction, int>()
			{
																{ OpCodes.Call.ToInstruction(importer.Import(typeof(Math).GetMethod("Floor", new Type[] { typeof(double) }))), i + 1},
																{ OpCodes.Conv_I4.ToInstruction(), i + 2}
			}
			);
		}

		private static double RandomNumberBetween(double minValue, double maxValue)
		{
			var next = new Random().NextDouble();
			return minValue + (next * (maxValue - minValue));
		}


		private void roundReplacer()
		{
			double newoperand = operand + RandomNumberBetween(0.01, 0.5);
			instructions[i] = OpCodes.Ldc_R8.ToInstruction(newoperand);
			DnlibUtils.InsertInstructions(instructions,
			new Dictionary<Instruction, int>()
			{
																{ OpCodes.Call.ToInstruction(importer.Import(typeof(Math).GetMethod("Round", new Type[] { typeof(double) }))), i + 1},
																{ OpCodes.Conv_I4.ToInstruction(), i + 2}
			}
			);
		}

		private void localReplacer()
		{
			Local local = new Local(importer.ImportAsTypeSig(typeof(int)));
			body.Variables.Add(local);
			DnlibUtils.InsertInstructions(instructions,
			new Dictionary<Instruction, int>()
			{
																{ OpCodes.Stloc_S.ToInstruction(local), 1},
																{ Instruction.CreateLdcI4(operand), 1}
			});
			i += 2;

			instructions[i] = OpCodes.Ldloc_S.ToInstruction(local);

		}



		private void sqrtReplacer(ref int forward)
		{
			bool isLower = operand < 0;
			if (isLower) operand *= -1;
			double newoperand = Math.Pow(operand, 2);
			instructions[i] = OpCodes.Ldc_R8.ToInstruction(newoperand);
			instructions.Insert(i + 1, OpCodes.Call.ToInstruction(importer.Import(typeof(Math).GetMethod("Sqrt", new Type[] { typeof(double) }))));
			instructions.Insert(i + 2, OpCodes.Conv_I4.ToInstruction());
			forward += 2;
			if (isLower)
			{
				DnlibUtils.InsertInstructions(instructions,
				new Dictionary<Instruction, int>()
				{
																				{ Instruction.CreateLdcI4(-1), i + 3},
																				{ OpCodes.Mul.ToInstruction(), i + 4}
				}
				);

				forward += 2;
			}
		}



		private void structReplacer(ref int forward)
		{
			bool isLower = operand < 0;
			if (isLower) operand *= -1;
			if (operand > 500) return;
			TypeDef typeDef = Utils.CreateStruct(importer, operand);
			module.Types.Add(typeDef);
			instructions[i] = OpCodes.Sizeof.ToInstruction(typeDef);
			if (isLower)
			{
				DnlibUtils.InsertInstructions(instructions,
				new Dictionary<Instruction, int>()
				{
																				{ Instruction.CreateLdcI4(-1), i + 1},
																				{ OpCodes.Mul.ToInstruction(), i + 2}
				}
				);
				forward += 2;
			}
		}

		private void emptyTypes()
		{
			instructions[i] = OpCodes.Ldsfld.ToInstruction(importer.Import(typeof(Type).GetField("EmptyTypes")));
			DnlibUtils.InsertInstructions(instructions,
			new Dictionary<Instruction, int>()
			{
																{ OpCodes.Ldlen.ToInstruction(), i + 1},
			}
			);
		}

		private void sizeofReplacer()
		{
			instructions[i] = Utils.GetSizeofInstruction(importer, operand);
		}




	}
}
