using System.Collections.Generic;
using System.IO;
using dnlib.DotNet.Writer;


namespace Eddy_Protector.Virtualization.RT
{
	internal class KoiHeap : HeapBase
	{
		private readonly List<byte[]> chunks = new List<byte[]>();
		private uint currentLen;

		public override string Name => "Eddy^CZ";

		public uint AddChunk(byte[] chunk)
		{
			var offset = currentLen;
			chunks.Add(chunk);
			currentLen += (uint)chunk.Length;
			return offset;
		}

		public override uint GetRawLength()
		{
			return currentLen;
		}

		protected override void WriteToImpl(BinaryWriter writer)
		{
			foreach (var chunk in chunks)
				writer.Write(chunk);
		}
	}
}