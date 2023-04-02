using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Eddy_Protector_Protections.Protections.ControlFlow2
{
	internal static class BlockParser
	{
		public static ScopeBlock ParseBody(CilBody body)
		{
			Dictionary<ExceptionHandler, Tuple<ScopeBlock, ScopeBlock, ScopeBlock>> dictionary = new Dictionary<ExceptionHandler, Tuple<ScopeBlock, ScopeBlock, ScopeBlock>>();
			foreach (ExceptionHandler handler in body.ExceptionHandlers)
			{
				ScopeBlock block = new ScopeBlock(BlockType.Try, handler);
				BlockType @finally = BlockType.Handler;
				if (handler.HandlerType == ExceptionHandlerType.Finally)
				{
					@finally = BlockType.Finally;
				}
				else if (handler.HandlerType == ExceptionHandlerType.Fault)
				{
					@finally = BlockType.Fault;
				}
				ScopeBlock block2 = new ScopeBlock(@finally, handler);
				if (handler.FilterStart != null)
				{
					ScopeBlock block3 = new ScopeBlock(BlockType.Filter, handler);
					dictionary[handler] = Tuple.Create<ScopeBlock, ScopeBlock, ScopeBlock>(block, block2, block3);
				}
				else
				{
					dictionary[handler] = Tuple.Create<ScopeBlock, ScopeBlock, ScopeBlock>(block, block2, null);
				}
			}
			ScopeBlock item = new ScopeBlock(BlockType.Normal, null);
			Stack<ScopeBlock> stack = new Stack<ScopeBlock>();
			stack.Push(item);
			foreach (Instruction instruction in body.Instructions)
			{
				foreach (ExceptionHandler handler2 in body.ExceptionHandlers)
				{
					Tuple<ScopeBlock, ScopeBlock, ScopeBlock> local1 = dictionary[handler2];
					if (instruction == handler2.TryEnd)
					{
						stack.Pop();
					}
					if (instruction == handler2.HandlerEnd)
					{
						stack.Pop();
					}
					if ((handler2.FilterStart != null) && (instruction == handler2.HandlerStart))
					{
						stack.Pop();
					}
				}
				foreach (ExceptionHandler handler3 in body.ExceptionHandlers.Reverse<ExceptionHandler>())
				{
					Tuple<ScopeBlock, ScopeBlock, ScopeBlock> tuple = dictionary[handler3];
					ScopeBlock block5 = (stack.Count > 0) ? stack.Peek() : null;
					if (instruction == handler3.TryStart)
					{
						if (block5 != null)
						{
							block5.Children.Add(tuple.Item1);
						}
						stack.Push(tuple.Item1);
					}
					if (instruction == handler3.HandlerStart)
					{
						if (block5 != null)
						{
							block5.Children.Add(tuple.Item2);
						}
						stack.Push(tuple.Item2);
					}
					if (instruction == handler3.FilterStart)
					{
						if (block5 != null)
						{
							block5.Children.Add(tuple.Item3);
						}
						stack.Push(tuple.Item3);
					}
				}
				ScopeBlock block6 = stack.Peek();
				InstrBlock block7 = block6.Children.LastOrDefault<BlockBase>() as InstrBlock;
				if (block7 == null)
				{
					block6.Children.Add(block7 = new InstrBlock());
				}
				block7.Instructions.Add(instruction);
			}
			foreach (ExceptionHandler handler4 in body.ExceptionHandlers)
			{
				if (handler4.TryEnd == null)
				{
					stack.Pop();
				}
				if (handler4.HandlerEnd == null)
				{
					stack.Pop();
				}
			}
			return item;
		}
	}
}

