﻿using System;
using System.Linq;


namespace Eddy_Protector.Virtualization.VM
{
	public class RegisterDescriptor
	{
		private readonly byte[] regOrder = Enumerable.Range(0, (int)VMRegisters.Max).Select(x => (byte)x).ToArray();

		public RegisterDescriptor(Random random)
		{
			random.Shuffle(regOrder);
		}

		public byte this[VMRegisters reg] => regOrder[(int)reg];
	}
}