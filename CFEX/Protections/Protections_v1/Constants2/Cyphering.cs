using Eddy_Protector_Core.Core.Poly;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Eddy_Protector_Protections.Protections.Constants2
{
 class Cyphering
 {
  public byte[] Encrypt(byte[] bytes, Expression exp)
  {
   MemoryStream ret = new MemoryStream();
   using (BinaryWriter wtr = new BinaryWriter(ret))
   {
    for (int i = 0; i < bytes.Length; i++)
    {
     int en = (int)ExpressionEvaluator.Evaluate(exp, bytes[i]);
     Write7BitEncodedInt(wtr, en);
    }
   }

   return ret.ToArray();
  }
  public byte[] EncryptSafe(byte[] bytes, uint key)
  {
   ushort _m = (ushort)(key >> 16);
   ushort _c = (ushort)(key & 0xffff);
   ushort m = _c; ushort c = _m;
   byte[] ret = (byte[])bytes.Clone();
   for (int i = 0; i < ret.Length; i++)
   {
    ret[i] ^= (byte)((key * m + c) % 0x100);
    m = (ushort)((key * m + _m) % 0x10000);
    c = (ushort)((key * c + _c) % 0x10000);
   }
   return ret;
  }
  public byte[] XorCrypt(byte[] bytes, uint key)
  {
   byte[] ret = new byte[bytes.Length];
   byte[] keyBuff = BitConverter.GetBytes(key);
   for (int i = 0; i < ret.Length; i++)
    ret[i] = (byte)(bytes[i] ^ keyBuff[i % 4]);
   return ret;
  }
  public ulong ComputeHash(uint x, uint key, ulong init0, ulong init1, ulong init2)
  {
   ulong h = init0 * x;
   ulong h1 = init1;
   ulong h2 = init2;
   h1 = h1 * h;
   h2 = h2 * h;
   h = h * h;

   ulong hash = 0xCBF29CE484222325;
   while (h != 0)
   {
    hash *= 0x100000001B3;
    hash = (hash ^ h) + (h1 ^ h2) * key;
    h1 *= 0x811C9DC5;
    h2 *= 0xA2CEBAB2;
    h >>= 8;
   }
   return hash;
  }
  public ulong Combine(uint high, uint low)
  {
   return (((ulong)high) << 32) | (ulong)low;
  }
  public void Write7BitEncodedInt(BinaryWriter wtr, int value)
  {
   // Write out an int 7 bits at a time. The high bit of the byte,
   // when on, tells reader to continue reading more bytes.
   uint v = (uint)value; // support negative numbers
   while (v >= 0x80)
   {
    wtr.Write((byte)(v | 0x80));
    v >>= 7;
   }
   wtr.Write((byte)v);
  }
  public int Read7BitEncodedInt(BinaryReader rdr)
  {
   // Read out an int 7 bits at a time. The high bit
   // of the byte when on means to continue reading more bytes.
   int count = 0;
   int shift = 0;
   byte b;
   do
   {
    b = rdr.ReadByte();
    count |= (b & 0x7F) << shift;
    shift += 7;
   } while ((b & 0x80) != 0);
   return count;
  }

 }
}
