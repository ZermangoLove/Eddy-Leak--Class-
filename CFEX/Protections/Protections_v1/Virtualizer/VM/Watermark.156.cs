﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Eddy_Protector.Virtualization
{
		[Obfuscation(Exclude = false, Feature = "+koi;-ref proxy")]
		internal static class Watermark
		{
			internal static byte[] GenerateWatermark(uint rand)
			{
				uint id = 0x10000;
				var a = id * 0x94952c99; // 0x71b467a9
				var b = id * 0xbaaa9827; // 0x1edd5797
				var c = id * 0x6f3592e3; // 0x4fa242cb
				var d = a + b + c;

				var watermark = new byte[0x10];
				watermark[0x0] = (byte)(a >> 24);
				watermark[0x1] = (byte)(a >> 16);
				watermark[0x2] = (byte)(a >> 8);
				watermark[0x3] = (byte)(a >> 0);

				watermark[0x4] = (byte)(b >> 24);
				watermark[0x5] = (byte)(b >> 16);
				watermark[0x6] = (byte)(b >> 8);
				watermark[0x7] = (byte)(b >> 0);

				watermark[0x8] = (byte)(c >> 24);
				watermark[0x9] = (byte)(c >> 16);
				watermark[0xA] = (byte)(c >> 8);
				watermark[0xB] = (byte)(c >> 0);

				watermark[0xC] = (byte)(d >> 24);
				watermark[0xD] = (byte)(d >> 16);
				watermark[0xE] = (byte)(d >> 8);
				watermark[0xF] = (byte)(d >> 0);

				return watermark;
			}
		}
	}
