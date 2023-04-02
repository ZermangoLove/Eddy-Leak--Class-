﻿using System;
using System.Linq;
using Eddy_Protector.Virtualization.VMIL;


namespace Eddy_Protector.Virtualization.VM
{
	public class OpCodeDescriptor
	{
		private readonly byte[] opCodeOrder = Enumerable.Range(0, 256).Select(x => (byte)x).ToArray();

		public OpCodeDescriptor(Random random)
		{
			random.Shuffle(opCodeOrder);
		}

		public byte this[ILOpCode opCode] => opCodeOrder[(int)opCode];
	}
}