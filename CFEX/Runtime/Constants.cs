using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualBasic;

namespace Runtime
{
 internal static class Constants
 {

  public static string XXTEADecryptSTR(string data, DateTime key_)
  {
   /* XXTEA In one method modded by Eddy^CZ 2018 (17.12.2018) */

   /* DATA to long array */
   int len = data.Length / 16;
   long[] result_long = new long[len];
   for (int i = 0; i < len; i++)
   {
    result_long[i] = Convert.ToInt64(data.Substring(i * 16, 16), 16);
   }
   /* ----------------------------------------------------------------- */

   /* KEY to long array */
   byte[] key_b = Encoding.UTF8.GetBytes(key_.Ticks.ToString().PadRight(32, '\0'));

   int n0 = (key_b.Length % 8 == 0 ? 0 : 1) + key_b.Length / 8;
   long[] key_long = new long[n0];

   for (int i = 0; i < n0 - 1; i++)
   {
    key_long[i] = BitConverter.ToInt64(key_b, i * 8);
   }
   byte[] buffer = new byte[8];
   Array.Copy(key_b, (n0 - 1) * 8, buffer, 0, key_b.Length - (n0 - 1) * 8);
   key_long[n0 - 1] = BitConverter.ToInt64(buffer, 0);
   /* ------------------------------------------------------------------ */

   /* Decrypt XXTEA */
   int n = result_long.Length;
   if (n < 1) { return data; }
   long z = result_long[result_long.Length - 1], y = result_long[0], sum = 0, e, p, q;
   q = 6 + 52 / n;
   sum = q * 0x9E3779B9;
   while (sum != 0)
   {
    e = (sum >> 2) & 3;
    for (p = n - 1; p > 0; p--)
    {
     z = result_long[p - 1];
     y = result_long[p] -= (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (key_long[p & 3 ^ e] ^ z);
    }
    z = result_long[n - 1];
    y = result_long[0] -= (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (key_long[p & 3 ^ e] ^ z);
    sum -= 0x9E3779B9;
   }
   /* ------------------------------------------------------------------------------------------------------ */

   /* Get BYTE[] from decrypted */
   List<byte> result = new List<byte>(result_long.Length * 8);
   for (int i = 0; i < result_long.Length; i++)
   {
    result.AddRange(BitConverter.GetBytes(result_long[i]));
   }
   while (result[result.Count - 1] == '\0')
   {
    result.RemoveAt(result.Count - 1);
   }
   byte[] result_b = result.ToArray();
   return Encoding.UTF8.GetString(result_b, 0, result_b.Length);
   /* ----------------------------------------------------------------- */
  }

  public static int RSADecryptLDCI4(string data, string modulus, string exponent, string p, string q, string dp, string dq, string inverseq, string d)
  {

   /* Input HEX to byte[] */
   int len = data.Length;
   byte[] bytes = new byte[len / 2];
   for (int i = 0; i < len; i += 2)
   {
    bytes[i / 2] = Convert.ToByte(data.Substring(i, 2), 16);
   }
   /* ---------------------------------------------------------- */

   /* Get RSA Parameters from arguments */
   RSAParameters rsa_params = new RSAParameters();
   rsa_params.Modulus = Encoding.Default.GetBytes(modulus);
   rsa_params.Exponent = Encoding.Default.GetBytes(exponent);
   rsa_params.P = Encoding.Default.GetBytes(p);
   rsa_params.Q = Encoding.Default.GetBytes(q);
   rsa_params.DP = Encoding.Default.GetBytes(dp);
   rsa_params.DQ = Encoding.Default.GetBytes(dq);
   rsa_params.InverseQ = Encoding.Default.GetBytes(inverseq);
   rsa_params.D = Encoding.Default.GetBytes(d);
   /* -----------------------------------------------------------*/

   /* Create instance of RSA and import parameters */
   RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
   rsa.ImportParameters(rsa_params);
   /* -------------------------------------------------------------*/

   /* RSA Decrypt */
   byte[] decoded = rsa.Decrypt(bytes, false);
   /* ------------------------------------------*/

   /* Result byte[] to Int32 */
   int result = BitConverter.ToInt32(decoded, 0);
   return result;
   /* -------------------------------------------------------------*/
  }

  ///// <summary>
  ///// Decryption for RC6
  ///// </summary>
  ///// <param name="key">Key as Uint number</param>
  ///// <param name="input">Data to decrypt</param>
  ///// <returns></returns>
  //public static uint BigNumberDecoder(string input_str, int P32, int Q32)
  //{

  // uint K0 = (uint)P32;
  // uint K1 = (uint)Q32;

  // uint Q = ((K1 >> 24) & 0xff);
  // uint G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
  // uint G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
  // uint deriver = ((K1 << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
  // Q = ((deriver >> 24) & 0xff);
  // G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
  // G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
  // deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
  // Q = ((deriver >> 24) & 0xff);
  // G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
  // G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
  // deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
  // Q = ((deriver >> 24) & 0xff);
  // G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
  // G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
  // deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
  // deriver ^= K0;
  // Q = ((deriver >> 24) & 0xff);
  // G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
  // G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
  // deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
  // Q = ((deriver >> 24) & 0xff);
  // G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
  // G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
  // deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
  // Q = ((deriver >> 24) & 0xff);
  // G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
  // G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
  // deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
  // Q = ((deriver >> 24) & 0xff);
  // G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
  // G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
  // deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);

  // uint key = deriver;

  // /* Decode input_str */
  // System.Text.RegularExpressions.MatchCollection finder = System.Text.RegularExpressions.Regex.Matches(input_str, @"\{([^\}]+)\}");
  // List<int> n_buffer = new List<int>();
  // foreach (System.Text.RegularExpressions.Match match in finder)
  // {
  //  n_buffer.Add(int.Parse(match.ToString().Replace("{", "").Replace("}", "")));
  // }
  // int[] numbers = n_buffer.ToArray();
  // int key_ = numbers[16];

  // List<byte> buffer = new List<byte>();
  // int counter = 0;
  // foreach (var n in numbers)
  // {
  //  counter++;
  //  int num0 = key_ ^ n;
  //  buffer.Add((byte)num0);
  //  if (counter == 16) break;
  // }

  // byte[] input = buffer.ToArray();


  // const int R = 16;
  // const int W = 32;
  // UInt32[] KEYS = new UInt32[2 * R + 4];
  // int nLgw = (int)(Math.Log((double)W) / Math.Log(2.0));

  // /* Generate keys Uint32[] */
  // //UInt32 P32 = 0xB7E15163;
  // //UInt32 Q32 = 0x9E3779B9;
  // UInt32 F, A, B;
  // UInt32 dwByteOne, dwByteTwo, dwByteThree, dwByteFour;
  // dwByteOne = key >> 24;
  // dwByteTwo = key >> 8;
  // dwByteTwo = dwByteTwo & 0x0010;
  // dwByteThree = key << 8;
  // dwByteThree = dwByteThree & 0x0100;
  // dwByteFour = key << 24;
  // key = dwByteOne | dwByteTwo | dwByteThree | dwByteFour;
  // KEYS[0] = (uint)P32;
  // for (F = 1; F < 2 * R + 4; F++)
  // {
  //  KEYS[F] = KEYS[F - 1] + (uint)Q32;
  // }
  // F = A = B = 0;
  // int v = 3 * Math.Max(1, 2 * R + 4);
  // for (int s = 1; s <= v; s++)
  // {
  //  int c = 3;
  //  c = c << (W - nLgw);
  //  c = c >> (W - nLgw);
  //  A = KEYS[F] = KEYS[F] + A + B << c | KEYS[F] + A + B >> W - c;
  //  int p = (int)(A + B);
  //  int nRgw = (int)(Math.Log((double)W) / Math.Log(2.0));
  //  p = p << (W - nRgw);
  //  p = p >> (W - nRgw);
  //  B = key = key + A + B << p | key + A + B >> W - p;
  //  F = (F + 1) % (2 * R + 4);
  // }
  // /* ---------------------------------------------------------------------- */
  // UInt32[] pdwTemp = null;
  // for (int i = 0; i < input.Length; i += 16)
  // {
  //  //pwdtemp =  convert from byte[] to uint
  //  List<UInt32> results = new List<UInt32>();
  //  int length = i + 16;
  //  for (int f = i; f < length; f += 4)
  //  {
  //   byte[] temp = new byte[4];
  //   for (int j = 0; j < 4; ++j)
  //   {
  //    if (i + j < input.Length)
  //     temp[j] = input[f + j];
  //    else
  //     temp[j] = 0x00;
  //   }
  //   results.Add(BitConverter.ToUInt32(temp, 0));
  //  }
  //  pdwTemp = results.ToArray();
  //  /* ------------------------------------------ */
  //  pdwTemp[1] = (pdwTemp[1] + KEYS[0]);
  //  pdwTemp[3] = (pdwTemp[3] + KEYS[1]);
  //  for (int j = 1; j <= R; j++)
  //  {
  //   int num_t_offset = (int)(Math.Log((double)W) / Math.Log(2.0));
  //   num_t_offset = num_t_offset << (W - nLgw);
  //   num_t_offset = num_t_offset >> (W - nLgw);
  //   uint num_t_leftside = (pdwTemp[1] * (2 * pdwTemp[1] + 1));
  //   uint num_t_left_shift = num_t_leftside << num_t_offset | num_t_leftside >> W - num_t_offset;
  //   UInt32 t = num_t_left_shift;
  //   int num_u_offset = (int)(Math.Log((double)W) / Math.Log(2.0));
  //   num_u_offset = num_u_offset << (W - nLgw);
  //   num_u_offset = num_u_offset >> (W - nLgw);
  //   uint num_u_leftside = (pdwTemp[3] * (2 * pdwTemp[3] + 1));
  //   uint num_u_left_shift = num_u_leftside << num_u_offset | num_u_leftside >> W - num_u_offset;
  //   UInt32 u = num_u_left_shift;
  //   int pwdTemp0_offset = (int)u;
  //   pwdTemp0_offset = pwdTemp0_offset << (W - nLgw);
  //   pwdTemp0_offset = pwdTemp0_offset >> (W - nLgw);
  //   uint pwdTemp0_offset_leftSide = pdwTemp[0] ^ t;
  //   uint pwdTemp0_leftShift = pwdTemp0_offset_leftSide << pwdTemp0_offset | pwdTemp0_offset_leftSide >> W - pwdTemp0_offset;
  //   pdwTemp[0] = pwdTemp0_leftShift + KEYS[2 * j];
  //   int pwdTemp1_offset = (int)t;
  //   pwdTemp1_offset = pwdTemp1_offset << (W - nLgw);
  //   pwdTemp1_offset = pwdTemp1_offset >> (W - nLgw);
  //   uint pwdTemp1_offset_leftSide = pdwTemp[2] ^ u;
  //   uint pwdTemp1_leftShift = pwdTemp1_offset_leftSide << pwdTemp1_offset | pwdTemp1_offset_leftSide >> W - pwdTemp1_offset;
  //   pdwTemp[2] = pwdTemp1_leftShift + KEYS[2 * j + 1];
  //   UInt32 temp = pdwTemp[0];
  //   pdwTemp[0] = pdwTemp[1];
  //   pdwTemp[1] = pdwTemp[2];
  //   pdwTemp[2] = pdwTemp[3];
  //   pdwTemp[3] = temp;
  //  }
  //  pdwTemp[0] = (pdwTemp[0] + KEYS[2 * R + 2]);
  //  pdwTemp[2] = (pdwTemp[2] + KEYS[2 * R + 3]);
  // }
  // List<byte> decrypted_buff = new List<byte>();

  // foreach (UInt32 value in pdwTemp)
  // {
  //  byte[] converted = BitConverter.GetBytes(value);
  //  decrypted_buff.AddRange(converted);
  // }
  // byte[] result = decrypted_buff.ToArray();
  // Array.Resize(ref result, result.Length - 9);

  // return BitConverter.ToUInt32(result, 0);
  //}

  #region Numis
  //public static int DecryptLdcI4(int input, double Key)
  //{
  // byte[] KEY = (BitConverter.GetBytes(Key));
  // int IV0 = 0;
  // int IV1 = 0;
  // int IV2 = 0;
  // int IV3 = 0;
  // int[] IVS = new int[KEY.Length];
  // for (int a = 0; a < IVS.Length; a++)
  // {
  //  IVS[a] = KEY[a] % (a + 1) ^ (int)input ^ (a + 1) ^ (int)input;
  // }
  // for (int i = 0; i < IVS.Length; i++)
  // {
  //  int X = (int)Math.Log10(IVS[i]);
  //  IV0 ^= IVS[i] ^ (((IVS[i] ^ (int)X)) * i >> (int)((float)i * (float)0.25F));
  //  IV1 += IVS[i] >> (((IVS[i] ^ (int)X)) * i << (int)((short)i + (float)0.58F));
  //  IV2 -= IVS[i] << (((IVS[i] ^ (int)X)) * i >> (int)((float)i * (float)0.41F));
  //  IV3 ^= IVS[i] + (((IVS[i] ^ (int)X)) * i << (int)((float)i - (float)0.99F));
  // }
  // return (IV0 ^ input) ^ (IV1 ^ input) ^ (IV2 ^ input) ^ IV3;
  //}

  //public static int PolyDexDecrypt(string input, double Key)
  //{
  // byte[] plain = Encoding.Default.GetBytes(input);
  // byte[] key = BitConverter.GetBytes(Key);
  // byte[] expandedKey;
  // byte[] dKey = key;
  // int length = plain.Length;
  // if (dKey.Length >= length) expandedKey = dKey;
  // else
  // {
  //  byte[] rconst = BitConverter.GetBytes(Math.Round(Math.PI, 3));
  //  byte[] result = new byte[length];
  //  Buffer.BlockCopy(dKey, 0, result, 0, dKey.Length);
  //  for (int i = dKey.Length; i < length; i++)
  //   result[i] = (byte)((dKey[(i - dKey.Length) % dKey.Length] ^ (result[i - 1])) % 256);
  //  for (int round = 0; round < 5; round++)
  //  {
  //   result[0] = (byte)(result[0] ^ rconst[round]);
  //   for (int i = 1; i < result.Length; i++)
  //    result[i] = (byte)(((result[i] ^ (byte)(rconst[round] << (i % 3))) ^ result[i - 1]) % 256);
  //  }
  //  expandedKey = result;
  // }
  // byte[] wholeState = plain;
  // byte magic = plain[plain.Length - 1];
  // Array.Resize(ref wholeState, wholeState.Length - 1);
  // for (int i = 0; i < wholeState.Length; i++) wholeState[i] = (byte)(wholeState[i] ^ magic ^ expandedKey[i]);
  // string str = Encoding.Default.GetString(wholeState);
  // return int.Parse(str);
  //}

  #endregion

  #region RC4 encryption
  //public static string Rc4Decrypt(string Data, int key_)
  //{
  // byte[] bytes = Encoding.Default.GetBytes(Data);
  // byte[] key = SHA512.Create().ComputeHash(BitConverter.GetBytes(key_)); //Create key!

  // int IV = 256;

  // byte[] s = new byte[IV];
  // byte[] k = new byte[IV];
  // byte temp;
  // int i, j;
  // for (i = 0; i < IV; i++)
  // {
  //  s[i] = (Byte)i;
  //  k[i] = key[i % key.GetLength(0)];
  // }
  // j = 0;
  // for (i = 0; i < IV; i++)
  // {
  //  j = (j + s[i] + k[i]) % IV;
  //  temp = s[i];
  //  s[i] = s[j];
  //  s[j] = temp;
  // }
  // i = j = 0;
  // for (int x = 0; x < bytes.GetLength(0); x++)
  // {
  //  i = (i + 1) % IV;
  //  j = (j + s[i]) % IV;
  //  temp = s[i];
  //  s[i] = s[j];
  //  s[j] = temp;
  //  int t = (s[i] + s[j]) % IV;
  //  bytes[x] ^= s[t];
  // }
  // return Encoding.Default.GetString(bytes);
  //}
  #endregion
 }
}
