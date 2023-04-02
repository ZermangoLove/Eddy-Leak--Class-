using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualBasic;

namespace Eddy_Protector_Protections.Protections.StringEncrypt
{
 public class Encryption
 {
  internal ConstantContext ctx;


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

  public string Rc4Encrypt(string Data, int key)
  {
   byte[] input = Encoding.Default.GetBytes(Data);
   int num;

   int IV = 256;

   byte num3;
   byte[] bytes = SHA512.Create().ComputeHash(BitConverter.GetBytes(key));//Create key
   byte[] buffer2 = new byte[IV];
   byte[] buffer3 = new byte[IV];
   for (num = 0; num < IV; num++)
   {
    buffer2[num] = (byte)num;
    buffer3[num] = bytes[num % bytes.GetLength(0)];
   }
   int index = 0;
   for (num = 0; num < IV; num++)
   {
    index = ((index + buffer2[num]) + buffer3[num]) % IV;
    num3 = buffer2[num];
    buffer2[num] = buffer2[index];
    buffer2[index] = num3;
   }
   num = index = 0;
   for (int i = 0; i < input.GetLength(0); i++)
   {
    num = (num + 1) % IV;
    index = (index + buffer2[num]) % IV;
    num3 = buffer2[num];
    buffer2[num] = buffer2[index];
    buffer2[index] = num3;
    int num5 = (buffer2[num] + buffer2[index]) % IV;
    input[i] = (byte)(input[i] ^ buffer2[num5]);
   }
   return Encoding.Default.GetString(input);
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


  #region OldStuff

  //public void EncryptLDCI4(int CurrentPos, MethodDef method, Instruction ins, MethodDef TargetMethod) //Int32
  //{

  // Importer importer = new Importer(ctx.context.CurrentModule, ImporterOptions.TryToUseDefs);

  // long key = ctx.context.generator.RandomUint();

  // var key_sqrt = Math.Cos(key);

  // ins.OpCode = OpCodes.Ldstr;

  // var EncryptedOperrand = XXTEAEncryptSTR(int.Parse(ins.Operand.ToString()), key_sqrt);

  // int DecryptTest = PolyDexDecrypt(EncryptedOperrand, key_sqrt);

  //	ins.Operand = EncryptedOperrand;
  //	method.Body.Instructions.Insert(CurrentPos + 1, OpCodes.Ldc_R8.ToInstruction(key_sqrt));
  // method.Body.Instructions.Insert(CurrentPos + 2, new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Cos", new Type[] { typeof(double) }))));

  // #region Old
  // //method.Body.Instructions.Insert(CurrentPos + 2, new Instruction(OpCodes.Ldc_I4, IV));
  // //method.Body.Instructions.Insert(CurrentPos + 3, new Instruction(OpCodes.Xor));
  // #endregion

  // method.Body.Instructions.Insert(CurrentPos + 3, new Instruction(OpCodes.Call, TargetMethod));
  //	ctx.UsedKeysLdci4.Add(key_sqrt.ToString());
  //}

  #endregion

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

  static FieldDef InjectArray(ModuleDefMD mod, byte[] injectedData, string injectedName)
  {
   // we'll have to import lots of new stuff into our module
   Importer importer = new Importer(mod);

   // add class with layout
   ITypeDefOrRef valueTypeRef = importer.Import(typeof(System.ValueType));
   TypeDef classWithLayout = new TypeDefUser("dummyClass", valueTypeRef);
   classWithLayout.Attributes |= TypeAttributes.Sealed | TypeAttributes.ExplicitLayout;
   classWithLayout.ClassLayout = new ClassLayoutUser(1, (uint)injectedData.Length);
   mod.Types.Add(classWithLayout);

   // add field with proper InitialValue
   FieldDef fieldWithRVA = new FieldDefUser("dummyField", new FieldSig(classWithLayout.ToTypeSig()), FieldAttributes.Static | FieldAttributes.Assembly | FieldAttributes.HasFieldRVA);
   fieldWithRVA.InitialValue = injectedData;
   mod.GlobalType.Fields.Add(fieldWithRVA);

   // add byte[] field
   ITypeDefOrRef byteArrayRef = importer.Import(typeof(System.Byte[]));
   FieldDef fieldInjectedArray = new FieldDefUser(injectedName, new FieldSig(byteArrayRef.ToTypeSig()), FieldAttributes.Static | FieldAttributes.Public);
   mod.GlobalType.Fields.Add(fieldInjectedArray);

   // and finally add code to global .cctor to initialize array.
   /*
     ldc.i4     XXXsizeofarrayXXX
     newarr     [mscorlib]System.Byte
     dup
     ldtoken    field valuetype className fieldName
     call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array, valuetype [mscorlib]System.RuntimeFieldHandle)
     stsfld     uint8[] bla
    */
   ITypeDefOrRef systemByte = importer.Import(typeof(System.Byte));
   ITypeDefOrRef runtimeHelpers = importer.Import(typeof(System.Runtime.CompilerServices.RuntimeHelpers));
   IMethod initArray = importer.Import(typeof(System.Runtime.CompilerServices.RuntimeHelpers).GetMethod("InitializeArray", new Type[] { typeof(System.Array), typeof(System.RuntimeFieldHandle) }));

   MethodDef cctor = mod.GlobalType.FindOrCreateStaticConstructor();
   IList<Instruction> instrs = cctor.Body.Instructions;
   instrs.Insert(0, new Instruction(OpCodes.Ldc_I4, injectedData.Length));
   instrs.Insert(1, new Instruction(OpCodes.Newarr, systemByte));
   instrs.Insert(2, new Instruction(OpCodes.Dup));
   instrs.Insert(3, new Instruction(OpCodes.Ldtoken, fieldWithRVA));
   instrs.Insert(4, new Instruction(OpCodes.Call, initArray));
   instrs.Insert(5, new Instruction(OpCodes.Stsfld, fieldInjectedArray));

   return fieldInjectedArray;
  }


  public void EncryptLDCI4(int CurrentPos, MethodDef method, Instruction ins, MethodDef Decryption)
  {

   //var tst_arr = InjectArray(ctx.context.CurrentModule, new byte[] { 1, 2, 3, 4, 5, 6 }, "hello world!");

   var p = GenerateRSAParameters();
   var EncryptedOperrand = RSAEncryptLDCI(int.Parse(ins.Operand.ToString()), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

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
   //method.Body.Instructions.Insert(CurrentPos + 9, new Instruction(OpCodes.Ldsfld, tst_arr));
   method.Body.Instructions.Insert(CurrentPos + 9, new Instruction(OpCodes.Call, Decryption));

  }

  public void RandomMathInstruction(double key, out double number, out Instruction InstructionMath)
  {
   Importer importer = new Importer(ctx.context.CurrentModule, ImporterOptions.TryToUseDefs);
   InstructionMath = null;
   number = 0;
   switch (new Random().Next(8))
   {
    case 0:
     InstructionMath = new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Tan", new Type[] { typeof(double) })));
     number = Math.Tan(key);
     break;
    case 1:
     InstructionMath = new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Tanh", new Type[] { typeof(double) })));
     number = Math.Tanh(key);
     break;
    case 2:
     InstructionMath = new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Sinh", new Type[] { typeof(double) })));
     number = Math.Sinh(key);
     break;
    case 3:
     InstructionMath = new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Atan", new Type[] { typeof(double) })));
     number = Math.Atan(key);
     break;
    case 4:
     InstructionMath = new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Asin", new Type[] { typeof(double) })));
     number = Math.Asin(key);
     break;
    case 5:
     InstructionMath = new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Log10", new Type[] { typeof(double) })));
     number = Math.Log10(key);
     break;
    case 6:
     InstructionMath = new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Exp", new Type[] { typeof(double) })));
     number = Math.Exp(key);
     break;
    case 7:
     InstructionMath = new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Log", new Type[] { typeof(double) })));
     number = Math.Log(key);
     break;
    case 8:
     InstructionMath = new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Round", new Type[] { typeof(double) })));
     number = Math.Round(key);
     break;
    case 9:
     InstructionMath = new Instruction(OpCodes.Call, importer.Import(typeof(Math).GetMethod("Sqrt", new Type[] { typeof(double) })));
     number = Math.Sqrt(key);
     break;
    case 10:

     break;
   }
  }

  public void RandomDateTimePair(long key, out DateTime date,  out Instruction ins)
  {
   Importer importer = new Importer(ctx.context.CurrentModule, ImporterOptions.TryToUseDefs);
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


  public void EncryptLDSTR(int CurrentPos, MethodDef method, Instruction ins, MethodDef TargetMethod)
  {
   //long key = Math.Abs(ctx.context.generator.RandomLong()); //Generate key

   long key = RandomDate().ToBinary();

   Instruction MathIns = null;
   DateTime MathNum = DateTime.MaxValue;

   RandomDateTimePair(key, out MathNum, out MathIns);

   var EncryptedOperrand = XXTEAEncryptSTR(ins.Operand.ToString(), MathNum);
   ins.Operand = EncryptedOperrand;


   method.Body.Instructions.Insert(CurrentPos + 1, OpCodes.Ldc_I8.ToInstruction(key));
   method.Body.Instructions.Insert(CurrentPos + 2, MathIns);
   method.Body.Instructions.Insert(CurrentPos + 3, new Instruction(OpCodes.Call, TargetMethod));


   ctx.UsedKeysLdci4.Add(key.ToString());
  }
 }
}
