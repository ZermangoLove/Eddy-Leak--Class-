using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Eddy_Protector_Protections.Protections.ControlFlow2
{
	internal class JumpMangler : ManglerBase
	{
		public override void Mangle(CilBody body, ScopeBlock root, CFContext ctx)
		{
			body.MaxStack++;
			foreach (InstrBlock block in GetAllBlocks(root))
			{
				LinkedList<Instruction[]> fragments = SpiltFragments(block, ctx);
				if (fragments.Count < 4) continue;

				LinkedListNode<Instruction[]> current = fragments.First;
				while (current.Next != null)
				{
					var newFragment = new List<Instruction>(current.Value);
					ctx.AddJump(newFragment, current.Next.Value[0]);
					ctx.AddJunk(newFragment);
					current.Value = newFragment.ToArray();
					current = current.Next;
				}
				Instruction[] first = fragments.First.Value;
				fragments.RemoveFirst();
				Instruction[] last = fragments.Last.Value;
				fragments.RemoveLast();

				List<Instruction[]> newFragments = fragments.ToList();
				ctx.Random.Shuffle(newFragments);

				block.Instructions = first
								.Concat(newFragments.SelectMany(fragment => fragment))
								.Concat(last).ToList();
			}
		}

		private LinkedList<Instruction[]> SpiltFragments(InstrBlock block, CFContext ctx)
		{
			LinkedList<Instruction[]> list = new LinkedList<Instruction[]>();
			List<Instruction> list2 = new List<Instruction>();
			int num = -1;
			for (int i = 0; i < block.Instructions.Count; i++)
			{
				if (num != -1)
				{
					if (num > 0)
					{
						list2.Add(block.Instructions[i]);
						num--;
						continue;
					}
					list.AddLast(list2.ToArray());
					list2.Clear();
					num = -1;
				}
				if (block.Instructions[i].OpCode.OpCodeType == OpCodeType.Prefix)
				{
					num = 1;
					list2.Add(block.Instructions[i]);
				}
				if ((((i + 2) < block.Instructions.Count) && (block.Instructions[i].OpCode.Code == Code.Dup)) && ((block.Instructions[i + 1].OpCode.Code == Code.Ldvirtftn) && (block.Instructions[i + 2].OpCode.Code == Code.Newobj)))
				{
					num = 2;
					list2.Add(block.Instructions[i]);
				}
				if (((((i + 4) < block.Instructions.Count) && (block.Instructions[i].OpCode.Code == Code.Ldc_I4)) && ((block.Instructions[i + 1].OpCode.Code == Code.Newarr) && (block.Instructions[i + 2].OpCode.Code == Code.Dup))) && ((block.Instructions[i + 3].OpCode.Code == Code.Ldtoken) && (block.Instructions[i + 4].OpCode.Code == Code.Call)))
				{
					num = 4;
					list2.Add(block.Instructions[i]);
				}
				if ((((i + 1) < block.Instructions.Count) && (block.Instructions[i].OpCode.Code == Code.Ldftn)) && (block.Instructions[i + 1].OpCode.Code == Code.Newobj))
				{
					num = 1;
					list2.Add(block.Instructions[i]);
				}
				list2.Add(block.Instructions[i]);
				if (ctx.Intensity > ctx.Random.NextDouble())
				{
					list.AddLast(list2.ToArray());
					list2.Clear();
				}
			}
			if (list2.Count > 0)
			{
				list.AddLast(list2.ToArray());
			}
			return list;
		}
	}
}

