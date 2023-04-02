using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Protector.Utils;
using System.Security.Cryptography;

namespace Protector
{

 class Encryptors
 {
  public string XXTEAEncryptSTR(string data, DateTime key)
  {
   /* XXTEA In one method modded by Eddy^CZ 2018 (17.12.2018) */

   byte[] input_r = Encoding.UTF8.GetBytes(data.PadRight(32, '\0'));
   byte[] key_r = Encoding.UTF8.GetBytes(key.Ticks.ToString().PadRight(32, '\0'));

   /* Input to long array */
   int n0 = (input_r.Length % 8 == 0 ? 0 : 1) + input_r.Length / 8;
   long[] input_long = new long[n0];

   for (int i = 0; i < n0 - 1; i++)
   {
    input_long[i] = BitConverter.ToInt64(input_r, i * 8);
   }
   byte[] buffer0 = new byte[8];
   Array.Copy(input_r, (n0 - 1) * 8, buffer0, 0, input_r.Length - (n0 - 1) * 8);
   input_long[n0 - 1] = BitConverter.ToInt64(buffer0, 0);
   /* ------------------------------------------------ */

   /* Key to long array*/
   int n1 = (key_r.Length % 8 == 0 ? 0 : 1) + key_r.Length / 8;
   long[] key_long = new long[n1];

   for (int j = 0; j < n1 - 1; j++)
   {
    key_long[j] = BitConverter.ToInt64(key_r, j * 8);
   }
   byte[] buffer1 = new byte[8];
   Array.Copy(key_r, (n1 - 1) * 8, buffer1, 0, key_r.Length - (n1 - 1) * 8);
   key_long[n1 - 1] = BitConverter.ToInt64(buffer1, 0);
   /* ------------------------------------------------- */

   /* Encrypt XXTEA */
   int n = input_long.Length;
   if (n < 1) { Console.WriteLine("EEROR!"); }

   long z = input_long[input_long.Length - 1], y = input_long[0], sum = 0, e, p, q;
   q = 6 + 52 / n;
   while (q-- > 0)
   {
    sum += 0x9E3779B9;
    e = (sum >> 2) & 3;
    for (p = 0; p < n - 1; p++)
    {
     y = input_long[p + 1];
     z = input_long[p] += (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (key_long[p & 3 ^ e] ^ z);
    }
    y = input_long[0];
    z = input_long[n - 1] += (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (key_long[p & 3 ^ e] ^ z);
   }
   /* -------------------------------------------------- */

   /* Convert encrypted long array to HEX as result */
   StringBuilder sb = new StringBuilder();
   for (int i = 0; i < input_long.Length; i++)
   {
    sb.Append(input_long[i].ToString("x2").PadLeft(16, '0'));
   }
   return sb.ToString();
  }

  public string RSAEncryptLDCI(int data, string modulus, string exponent, string p, string q, string dp, string dq, string inverseq, string d)
  {
   /* Input data */
   byte[] data_b = BitConverter.GetBytes(data);
   /* ------------------------------------------------ */

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
   /* ---------------------------------------------------------------- */

   /* RSA Encrypt */
   byte[] data_e = rsa.Encrypt(data_b, false);
   /* ---------------------------------------------- */

   /* Encrypted byte[] to HEX */
   StringBuilder result = new StringBuilder(data_e.Length * 2);
   foreach (byte b in data_e)
   {
    result.AppendFormat("{0:x2}", b);
   }
   return result.ToString();
   /* -------------------------------------------------------- */
  }


 }

 class Generators
 {
  public string[] GenerateRSAParameters()
  {
   RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
   var rsa_params = rsa.ExportParameters(true);

   byte[] modulus = rsa_params.Modulus; //1
   byte[] exponent = rsa_params.Exponent;//2
   byte[] P = rsa_params.P;//3
   byte[] Q = rsa_params.Q;//4
   byte[] DP = rsa_params.DP;//5
   byte[] DQ = rsa_params.DQ;//6
   byte[] inverseQ = rsa_params.InverseQ;//7
   byte[] D = rsa_params.D;//8

   List<byte[]> rsa_parameters_l = new List<byte[]>();

   rsa_parameters_l.Add(modulus);//1
   rsa_parameters_l.Add(exponent);//2
   rsa_parameters_l.Add(P);//3
   rsa_parameters_l.Add(Q);//4
   rsa_parameters_l.Add(DP);//5
   rsa_parameters_l.Add(DQ);//6
   rsa_parameters_l.Add(inverseQ);//7
   rsa_parameters_l.Add(D);//8

   byte[][] rsa_parameters_arr = rsa_parameters_l.ToArray();

   string[] rsa_parameters_unicode = new string[rsa_parameters_arr.Length];

   for (int i = 0; i < rsa_parameters_arr.Length; i++)
   {
    string dta = Encoding.Default.GetString(rsa_parameters_arr[i]);
    rsa_parameters_unicode[i] = dta;
   }

   return rsa_parameters_unicode;
  }

  public void RandomDateTimePair(long key, out DateTime date, out Instruction ins)
  {
   Importer importer = new Importer(ConstantsProtection.Module, ImporterOptions.TryToUseDefs);
   ins = null;
   date = DateTime.MinValue;

   ins = new Instruction(OpCodes.Call, importer.Import(typeof(DateTime).GetMethod("FromBinary", new Type[] { typeof(long) })));
   date = DateTime.FromBinary(key);

  }

  public DateTime RandomDate()
  {
   long range = DateTime.MaxValue.ToBinary() - DateTime.MinValue.ToBinary();
   long randomTicks = DateTime.MinValue.Ticks + ((long)(new Random().NextDouble() * range));
   DateTime result = new DateTime(randomTicks);
   return result;
  }
 }

 class ConstantsProtection
 {
  public static ModuleDef Module;
  private MethodDef StringDecryptor;
  private MethodDef NumberDecryptor;
  private List<string> UsedKeysString = new List<string>();
  public ConstantsProtection(ModuleDef module)
  {
   Module = module;
   InjectDecrypters();
  }

  private void InjectDecrypters()
  {
   var rtType = DnLibHelper.GetRuntimeType("Runtime.Constants");
   IEnumerable<IDnlibDef> defs = InjectHelper.Inject(rtType, Module.EntryPoint.DeclaringType, Module);
   StringDecryptor = defs.OfType<MethodDef>().Single(method => method.Name == "XXTEADecryptSTR");
   NumberDecryptor = defs.OfType<MethodDef>().Single(method => method.Name == "RSADecryptLDCI4");
  }


  public void EncryptConstants(MethodDef method)
  {

   if (Engine.RuntimeMethods.Contains(method)) return;
   if (method == StringDecryptor || method == NumberDecryptor  || method.Name == "InitializeComponent") return;

   Module = method.Module;
   int insCnt = method.Body.Instructions.Count;

   for (int i = 0; i < insCnt; i++)
   {
    Instruction ins = method.Body.Instructions[i];
    if (ins.OpCode == OpCodes.Ldc_I4)
    {
     MethodDef DecMethod = NumberDecryptor;
     EncryptLDCI4(i, method, ins, DecMethod);
    }
   }

   for (int i = 0; i < insCnt; i++)
   {
    Instruction ins = method.Body.Instructions[i];
    if (ins.OpCode == OpCodes.Ldstr)
    {
     MethodDef DecMethod = StringDecryptor;
     EncryptLDSTR(i, method, ins, DecMethod);
    }
   }
  }

  public void EncryptConstants(ModuleDef module)
  {

   foreach (var t in module.GetTypes())
   {
    foreach (var m in t.Methods)
    {
     if(m.HasBody)
     {
      EncryptConstants(m);
     }

    }
   } 
  }

  private void EncryptLDCI4(int CurrentPos, MethodDef method, Instruction ins, MethodDef Decryption)
   {
    var p = new Generators().GenerateRSAParameters();
    var EncryptedOperrand = new Encryptors().RSAEncryptLDCI(int.Parse(ins.Operand.ToString()), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

    ins.OpCode = OpCodes.Ldstr;
    ins.Operand = EncryptedOperrand;

    method.Body.Instructions.Insert(CurrentPos + 1, new Instruction(OpCodes.Ldstr, p[0]));
    method.Body.Instructions.Insert(CurrentPos + 2, new Instruction(OpCodes.Ldstr, p[1]));
    method.Body.Instructions.Insert(CurrentPos + 3, new Instruction(OpCodes.Ldstr, p[2]));
    method.Body.Instructions.Insert(CurrentPos + 4, new Instruction(OpCodes.Ldstr, p[3]));
    method.Body.Instructions.Insert(CurrentPos + 5, new Instruction(OpCodes.Ldstr, p[4]));
    method.Body.Instructions.Insert(CurrentPos + 6, new Instruction(OpCodes.Ldstr, p[5]));
    method.Body.Instructions.Insert(CurrentPos + 7, new Instruction(OpCodes.Ldstr, p[6]));
    method.Body.Instructions.Insert(CurrentPos + 8, new Instruction(OpCodes.Ldstr, p[7]));
    method.Body.Instructions.Insert(CurrentPos + 9, new Instruction(OpCodes.Call, Decryption));

   }

  private void EncryptLDSTR(int CurrentPos, MethodDef method, Instruction ins, MethodDef TargetMethod)
   {

    long key = new Generators().RandomDate().ToBinary();

    Instruction MathIns = null;
    DateTime MathNum = DateTime.MaxValue;

   new Generators().RandomDateTimePair(key, out MathNum, out MathIns);

    var EncryptedOperrand = new Encryptors().XXTEAEncryptSTR(ins.Operand.ToString(), MathNum);
    ins.Operand = EncryptedOperrand;


    method.Body.Instructions.Insert(CurrentPos + 1, OpCodes.Ldc_I8.ToInstruction(key));
    method.Body.Instructions.Insert(CurrentPos + 2, MathIns);
    method.Body.Instructions.Insert(CurrentPos + 3, new Instruction(OpCodes.Call, TargetMethod));


   UsedKeysString.Add(key.ToString());
   }


  }
}
