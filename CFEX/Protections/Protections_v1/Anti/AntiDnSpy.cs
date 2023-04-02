/* Codded by: Eddy^CZ 2018 
   Date: 15.12.2018
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Eddy_Protector_Protections.Protections.Anti
{
	public class AntiDnSpy : ProtectionPhase
	{
		public override string Author => Engine.Author;
		public override string Description => "Hide real code from viewing in DnSpy all versions";
		public override string Id => Author+".AntiDnSpy";
		public override string Name => "Anti DnSpy";

  public List<MethodDef> Targets = new List<MethodDef>();

  public AntiDnSpy(object targets)
  {
   Targets = targets as List<MethodDef>;
  }


  public override void Execute(Context ctx)
		{
			var anti_dnspy = new RuntimeAntiDnspy();

			foreach (MethodDef method in Targets)
			{
				for (int a = 0; a < 1; a++)
				{
					anti_dnspy.DoAntiDnspySafe(method);
				}	
			}
		}
	}

	public class RuntimeAntiDnspy
	{

		public static OpCode op(string s)
		{
			switch (s)
			{
				case "ret": //0
					return OpCodes.Ret;
				case "calli": //1
					return OpCodes.Calli;
				case "sizeof": //2
					return OpCodes.Sizeof;
				case "stloc": //3
					return OpCodes.Stloc;
				default:
					return OpCodes.UNKNOWN2;
			}
		}

		public void DoAntiDnspySafe(MethodDef m)
		{
			m.Body.Instructions.Insert(m.Body.Instructions.Count - 1, new Instruction(OpCodes.Callvirt));
		}

		public void DoAntiDnspy(MethodDef method , Context ctx)
		{

			var m = method;

			if (m.HasBody && m.Body.HasInstructions)
			{

				#region Not used
				//int.Parse("42");
				#endregion

				Local var_0 = new Local(ctx.CurrentModule.Import(typeof(int)).ToTypeSig());
				Local var_1 = new Local(ctx.CurrentModule.Import(typeof(bool)).ToTypeSig());

				m.Body.Variables.Add(var_0);
				m.Body.Variables.Add(var_1);


				Instruction operand = null;
				//int z = 0;
				switch (new Random().Next(1))
				{
					case 0:
						operand = m.Body.Instructions[method.Body.Instructions.Count - sizeof(byte)];
						break;
					case 1:
						operand = m.Body.Instructions[method.Body.Instructions.Count - sizeof(uint)];
						break;
				}
				Instruction i_ret = new Instruction(OpCodes.Ret);
				Instruction i_ldc4 = new Instruction(OpCodes.Ldc_I4_1);

				/* Insert */
				m.Body.Instructions.Insert(0, new Instruction(OpCodes.Ldc_I4_0));
				m.Body.Instructions.Insert(1, new Instruction(op("stloc"), var_0));
				m.Body.Instructions.Insert(2, new Instruction(OpCodes.Br, i_ldc4));

				Instruction instruction3 = new Instruction(OpCodes.Ldloc, var_0);

				/* Insert */
				m.Body.Instructions.Insert(3, instruction3);
				m.Body.Instructions.Insert(4, new Instruction(OpCodes.Ldc_I4_0));
				m.Body.Instructions.Insert(5, new Instruction(OpCodes.Ceq));
				m.Body.Instructions.Insert(6, new Instruction(OpCodes.Ldc_I4_1));
				m.Body.Instructions.Insert(7, new Instruction(OpCodes.Ceq));
				m.Body.Instructions.Insert(8, new Instruction(op("stloc"), var_1));
				method.Body.Instructions.Insert(9, new Instruction(OpCodes.Ldloc, var_1));
				method.Body.Instructions.Insert(10, new Instruction(OpCodes.Brtrue, m.Body.Instructions[sizeof(Decimal) - 6]));

				#region Not used
				//Decimal.Round(new decimal(0));
				//bool flag = (165416541654 > 151515151 + Math.E ? flag = true : flag = false);
				#endregion

				//bool flag = true;

				switch (new Random().Next(1))
				{
					case 0:
						m.Body.Instructions.Insert(11, new Instruction(OpCodes.Ret));
						m.Body.Instructions.Insert(12, new Instruction(OpCodes.Calli));
						m.Body.Instructions.Insert(13, new Instruction(OpCodes.Sizeof, operand));
						m.Body.Instructions.Insert(m.Body.Instructions.Count, i_ldc4);
						m.Body.Instructions.Insert(m.Body.Instructions.Count, new Instruction(op("stloc"), var_1));
						m.Body.Instructions.Insert(m.Body.Instructions.Count, new Instruction(OpCodes.Br, instruction3));
						m.Body.Instructions.Insert(m.Body.Instructions.Count, i_ret);
						break;
					case 1:
						m.Body.Instructions.Insert(15, new Instruction(op("ret")));
						m.Body.Instructions.Insert(16, new Instruction(op("calli")));
						m.Body.Instructions.Insert(17, new Instruction(op("sizeof"), operand));
						m.Body.Instructions.Insert(18, new Instruction(op("calli")));
						m.Body.Instructions.Insert(m.Body.Instructions.Count, i_ldc4);
						m.Body.Instructions.Insert(m.Body.Instructions.Count, new Instruction(OpCodes.Stloc_S, var_1));
						m.Body.Instructions.Insert(m.Body.Instructions.Count, new Instruction(OpCodes.Br, instruction3));
						m.Body.Instructions.Insert(m.Body.Instructions.Count, i_ret);
						break;
				}

				ExceptionHandler exHandler = new ExceptionHandler(ExceptionHandlerType.Finally)
				{
					HandlerStart = m.Body.Instructions[10],
					HandlerEnd = m.Body.Instructions[11],
					TryEnd = m.Body.Instructions[14],
					TryStart = m.Body.Instructions[12]
				};

				#region Not used
				//float.IsNaN(0xffff);
				#endregion

				bool flag3 = !m.Body.HasExceptionHandlers;

				if (flag3)
				{
					method.Body.ExceptionHandlers.Add(exHandler);
				}

				operand = new Instruction(OpCodes.Br, i_ret);

				m.Body.Instructions.Insert(m.Body.Instructions.Count-1, new Instruction(OpCodes.Callvirt));
				m.Body.Instructions.Insert(m.Body.Instructions.Count-2,new Instruction(OpCodes.Sizeof));

				m.Body.OptimizeBranches();
				m.Body.OptimizeMacros();
			}
		}
	}
}
