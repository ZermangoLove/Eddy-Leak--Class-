using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Eddy_Protector_Protections.Protections.MathMutate
{
	class MathContext
	{
			public enum ArithmeticTypes
			{
				Add, // +
				Sub, // -
				Div, // /
				Mul, // *
				Xor, // ^
				Abs, // -1
				Log, //
				Log10,
				Sin,
				Cos,
				Round,
				Sqrt,
				Ceiling,
				Floor,
				Tan,
				Tanh,
				Truncate
			}

			public class ArithmeticEmulator
			{
				private double x;
				private double y;
				private ArithmeticTypes ArithmeticTypes;
				public ArithmeticTypes GetType { get; private set; }
				public ArithmeticEmulator(double x, double y, ArithmeticTypes ArithmeticTypes)
				{
					this.x = x;
					this.y = y;
					this.ArithmeticTypes = ArithmeticTypes;
				}
				public double GetValue()
				{
					switch (ArithmeticTypes)
					{
						case ArithmeticTypes.Add:
							return x - y;
						case ArithmeticTypes.Sub:
							return x + y;
						case ArithmeticTypes.Div:
							return x * y;
						case ArithmeticTypes.Mul:
							return x / y;
						case ArithmeticTypes.Xor:
							return ((int)x ^ (int)y);
					}
					return -1;
				}
				public double GetValue(List<ArithmeticTypes> arithmetics)
				{
					Generator generator = new Generator();
					ArithmeticTypes arithmetic = arithmetics[generator.Next(arithmetics.Count)];
					GetType = arithmetic;
					switch (ArithmeticTypes)
					{
						case ArithmeticTypes.Abs:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x + (Math.Abs(y) * -1);
								case ArithmeticTypes.Sub:
									return x - (Math.Abs(y) * -1);
							}
							return -1;
						case ArithmeticTypes.Log:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Log(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Log(y));
							}
							return -1;
						case ArithmeticTypes.Log10:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Log10(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Log10(y));
							}
							return -1;
						case ArithmeticTypes.Sin:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Sin(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Sin(y));
							}
							return -1;
						case ArithmeticTypes.Cos:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Cos(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Cos(y));
							}
							return -1;
						case ArithmeticTypes.Floor:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Floor(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Floor(y));
							}
							return -1;
						case ArithmeticTypes.Round:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Round(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Round(y));
							}
							return -1;
						case ArithmeticTypes.Tan:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Tan(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Tan(y));
							}
							return -1;
						case ArithmeticTypes.Tanh:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Tanh(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Tanh(y));
							}
							return -1;
						case ArithmeticTypes.Sqrt:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Sqrt(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Sqrt(y));
							}
							return -1;
						case ArithmeticTypes.Ceiling:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Ceiling(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Ceiling(y));
							}
							return -1;
						case ArithmeticTypes.Truncate:
							switch (arithmetic)
							{
								case ArithmeticTypes.Add:
									return x - (Math.Truncate(y));
								case ArithmeticTypes.Sub:
									return x + (Math.Truncate(y));
							}
							return -1;
					}
					return -1;
				}
				public double GetX() => x;
				public double GetY() => y;
			}

			public class Arithmetic
			{
				private ModuleDef moduleDef;
				List<iFunction> Tasks = new List<iFunction>()
								{
												new Add(),
												new Sub(),
												new Div(),
												new Mul(),
												new Xor(),
												new Abs(),
												new Log(),
												new Log10(),
												new Sin(),
												new Cos(),
												new Floor(),
												new Round(),
												new Tan(),
												new Tanh(),
												new Sqrt(),
												new Ceiling(),
												new Truncate()
								};
				public Arithmetic(ModuleDef moduleDef)
				{
					this.moduleDef = moduleDef;
				}

				public void Execute(MethodDef mDef)
				{
					Generator generator = new Generator();
					if (!mDef.HasBody) return;

					for (int i = 0; i < mDef.Body.Instructions.Count; i++)
					{
						if (ArithmeticUtils.CheckArithmetic(mDef.Body.Instructions[i]))
						{
							if (mDef.Body.Instructions[i].GetLdcI4Value() < 0)
							{
								iFunction iFunction = Tasks[generator.Next(5)];
								List<Instruction> lstInstr = GenerateBody(iFunction.Arithmetic(mDef.Body.Instructions[i], moduleDef));
								if (lstInstr == null) continue;
								mDef.Body.Instructions[i].OpCode = OpCodes.Nop;
								foreach (Instruction instr in lstInstr)
								{
									mDef.Body.Instructions.Insert(i + 1, instr);
									i++;
								}
							}
							else
							{
								iFunction iFunction = Tasks[generator.Next(Tasks.Count)];
								List<Instruction> lstInstr = GenerateBody(iFunction.Arithmetic(mDef.Body.Instructions[i], moduleDef));
								if (lstInstr == null) continue;
								mDef.Body.Instructions[i].OpCode = OpCodes.Nop;
								foreach (Instruction instr in lstInstr)
								{
									mDef.Body.Instructions.Insert(i + 1, instr);
									i++;
								}
							}
						}
					}
				}


				private List<Instruction> GenerateBody(ArithmeticVT arithmeticVTs)
				{
					List<Instruction> instructions = new List<Instruction>();
					if (IsArithmetic(arithmeticVTs.GetArithmetic()))
					{
						instructions.Add(new Instruction(OpCodes.Ldc_R8, arithmeticVTs.GetValue().GetX()));
						instructions.Add(new Instruction(OpCodes.Ldc_R8, arithmeticVTs.GetValue().GetY()));

						if (arithmeticVTs.GetToken().GetOperand() != null)
						{
							instructions.Add(new Instruction(OpCodes.Call, arithmeticVTs.GetToken().GetOperand()));
						}
						instructions.Add(new Instruction(arithmeticVTs.GetToken().GetOpCode()));
						instructions.Add(new Instruction(OpCodes.Call, moduleDef.Import(typeof(Convert).GetMethod("ToInt32", new Type[] { typeof(double) }))));
						//instructions.Add(new Instruction(OpCodes.Conv_I4));
					}
					else if (IsXor(arithmeticVTs.GetArithmetic()))
					{
						instructions.Add(new Instruction(OpCodes.Ldc_I4, (int)arithmeticVTs.GetValue().GetX()));
						instructions.Add(new Instruction(OpCodes.Ldc_I4, (int)arithmeticVTs.GetValue().GetY()));
						instructions.Add(new Instruction(arithmeticVTs.GetToken().GetOpCode()));
						instructions.Add(new Instruction(OpCodes.Conv_I4));
					}
					return instructions;
				}
				private bool IsArithmetic(ArithmeticTypes arithmetic)
				{
					return arithmetic == ArithmeticTypes.Add || arithmetic == ArithmeticTypes.Sub || arithmetic == ArithmeticTypes.Div || arithmetic == ArithmeticTypes.Mul ||
									arithmetic == ArithmeticTypes.Abs || arithmetic == ArithmeticTypes.Log || arithmetic == ArithmeticTypes.Log10 || arithmetic == ArithmeticTypes.Truncate ||
									arithmetic == ArithmeticTypes.Sin || arithmetic == ArithmeticTypes.Cos || arithmetic == ArithmeticTypes.Floor || arithmetic == ArithmeticTypes.Round ||
									arithmetic == ArithmeticTypes.Tan || arithmetic == ArithmeticTypes.Tanh || arithmetic == ArithmeticTypes.Sqrt || arithmetic == ArithmeticTypes.Ceiling;
				}
				private bool IsXor(ArithmeticTypes arithmetic)
				{
					return arithmetic == ArithmeticTypes.Xor;
				}
			}

			public class Value
			{
				private double x;
				private double y;
				public Value(double x, double y)
				{
					this.x = x;
					this.y = y;
				}
				public double GetX() => x;
				public double GetY() => y;
			}

			public class ArithmeticVT
			{
				private Value value;
				private Token token;
				private ArithmeticTypes arithmeticTypes;
				public ArithmeticVT(Value value, Token token, ArithmeticTypes arithmeticTypes)
				{
					this.value = value;
					this.token = token;
					this.arithmeticTypes = arithmeticTypes;
				}
				public Value GetValue() => value;
				public Token GetToken() => token;
				public ArithmeticTypes GetArithmetic() => arithmeticTypes;
			}

			public abstract class iArithmetic
			{
				public abstract string Name { get; }
				public abstract string Description { get; }
				public abstract void Init();
			}

			public abstract class iFunction
			{
				public abstract ArithmeticTypes ArithmeticTypes { get; }
				public abstract ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module);
			}

			public class Token
			{
				private OpCode opCode;
				private object Operand;
				public Token(OpCode opCode, object Operand)
				{
					this.opCode = opCode;
					this.Operand = Operand;
				}
				public Token(OpCode opCode)
				{
					this.opCode = opCode;
					this.Operand = null;
				}
				public OpCode GetOpCode() => opCode;
				public object GetOperand() => Operand;
			}


			#region Math functions
			public class Add : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Add;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(), arithmeticEmulator.GetY()), new Token(OpCodes.Add), ArithmeticTypes));
				}
			}

			public class Div : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Div;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(), arithmeticEmulator.GetY()), new Token(OpCodes.Div), ArithmeticTypes));
				}
			}

			public class Mul : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Mul;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(), arithmeticEmulator.GetY()), new Token(OpCodes.Mul), ArithmeticTypes));
				}
			}

			public class Sub : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Sub;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(), arithmeticEmulator.GetY()), new Token(OpCodes.Sub), ArithmeticTypes));
				}
			}
			public class Xor : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Xor;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), generator.Next(), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(), arithmeticEmulator.GetY()), new Token(OpCodes.Xor), ArithmeticTypes));
				}
			}

			public class Abs : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Abs;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}

			public class Ceiling : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Ceiling;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}
			public class Cos : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Cos;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}
			public class Floor : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Floor;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}

			public class Log : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Log;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}

			public class Log10 : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Log10;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}

			public class Round : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Round;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}

			public class Sin : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Sin;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}

			public class Sqrt : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Sqrt;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}

			public class Tan : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Tan;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}

			public class Tanh : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Tanh;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}

			public class Truncate : iFunction
			{
				public override ArithmeticTypes ArithmeticTypes => ArithmeticTypes.Truncate;
				public override ArithmeticVT Arithmetic(Instruction instruction, ModuleDef module)
				{
					Generator generator = new Generator();
					if (!ArithmeticUtils.CheckArithmetic(instruction)) return null;
					List<ArithmeticTypes> arithmeticTypes = new List<ArithmeticTypes>() { ArithmeticTypes.Add, ArithmeticTypes.Sub };
					ArithmeticEmulator arithmeticEmulator = new ArithmeticEmulator(instruction.GetLdcI4Value(), ArithmeticUtils.GetY(instruction.GetLdcI4Value()), ArithmeticTypes);
					return (new ArithmeticVT(new Value(arithmeticEmulator.GetValue(arithmeticTypes), arithmeticEmulator.GetY()), new Token(ArithmeticUtils.GetOpCode(arithmeticEmulator.GetType), module.Import(ArithmeticUtils.GetMethod(ArithmeticTypes))), ArithmeticTypes));
				}
			}
			#endregion

			public class Generator
			{
				private Random random;
				public Generator()
				{
					random = new Random(Guid.NewGuid().GetHashCode());
				}
				public int Next()
				{
					return random.Next(int.MaxValue);
				}
				public int Next(int value)
				{
					return random.Next(value);
				}
				public int Next(int min, int max)
				{
					return random.Next(min, max);
				}
			}

			public class ArithmeticUtils
			{
				public static bool CheckArithmetic(Instruction instruction)
				{
					if (!instruction.IsLdcI4())
						return false;
					if (instruction.GetLdcI4Value() == 1)
						return false;
					if (instruction.GetLdcI4Value() == 0)
						return false;
					return true;
				}
				public static double GetY(double x) => (x / 2);
				public static System.Reflection.MethodInfo GetMethod(ArithmeticTypes mathType)
				{
					switch (mathType)
					{
						case ArithmeticTypes.Abs:
							return ((typeof(Math).GetMethod("Abs", new Type[] { typeof(double) })));
						case ArithmeticTypes.Round:
							return ((typeof(Math).GetMethod("Round", new Type[] { typeof(double) })));
						case ArithmeticTypes.Sin:
							return ((typeof(Math).GetMethod("Sin", new Type[] { typeof(double) })));
						case ArithmeticTypes.Cos:
							return ((typeof(Math).GetMethod("Cos", new Type[] { typeof(double) })));
						case ArithmeticTypes.Log:
							return ((typeof(Math).GetMethod("Log", new Type[] { typeof(double) })));
						case ArithmeticTypes.Log10:
							return ((typeof(Math).GetMethod("Log10", new Type[] { typeof(double) })));
						case ArithmeticTypes.Sqrt:
							return ((typeof(Math).GetMethod("Sqrt", new Type[] { typeof(double) })));
						case ArithmeticTypes.Ceiling:
							return ((typeof(Math).GetMethod("Ceiling", new Type[] { typeof(double) })));
						case ArithmeticTypes.Floor:
							return ((typeof(Math).GetMethod("Floor", new Type[] { typeof(double) })));
						case ArithmeticTypes.Tan:
							return ((typeof(Math).GetMethod("Tan", new Type[] { typeof(double) })));
						case ArithmeticTypes.Tanh:
							return ((typeof(Math).GetMethod("Tanh", new Type[] { typeof(double) })));
						case ArithmeticTypes.Truncate:
							return ((typeof(Math).GetMethod("Truncate", new Type[] { typeof(double) })));
					}
					return null;
				}
				public static OpCode GetOpCode(ArithmeticTypes arithmetic)
				{
					switch (arithmetic)
					{
						case ArithmeticTypes.Add:
							return OpCodes.Add;
						case ArithmeticTypes.Sub:
							return OpCodes.Sub;
					}
					return null;
				}
			}

		}
}
