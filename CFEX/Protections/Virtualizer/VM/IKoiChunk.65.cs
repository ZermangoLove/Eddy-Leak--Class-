namespace Eddy_Protector.Virtualization.RT
{
	public interface IKoiChunk
	{
		uint Length
		{
			get;
		}

		void OnOffsetComputed(uint offset);
		byte[] GetData();
	}
}