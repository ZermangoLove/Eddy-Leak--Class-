using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Eddy_Protector.Protections.BigNumberProtection;
using System.Security.Cryptography;

namespace Eddy_Protector.Protections.BigNumberProtection
{
 class RC6LiteEncryption
 {
  /// <summary>
  /// Ecrypt for RC6
  /// </summary>
  /// <param name="key">Key as Uint number</param>
  /// <param name="input">Input data to encrypt</param>
  /// <returns></returns>
  public string Encrypt(int input_u, uint P32, uint Q32)
  {

   uint K0 = P32;
   uint K1 = Q32;

   uint Q = ((K1 >> 24) & 0xff);
   uint G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
   uint G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
   uint deriver = ((K1 << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
   Q = ((deriver >> 24) & 0xff);
   G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
   G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
   deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
   Q = ((deriver >> 24) & 0xff);
   G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
   G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
   deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
   Q = ((deriver >> 24) & 0xff);
   G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
   G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
   deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
   deriver ^= K0;
   Q = ((deriver >> 24) & 0xff);
   G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
   G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
   deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
   Q = ((deriver >> 24) & 0xff);
   G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
   G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
   deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
   Q = ((deriver >> 24) & 0xff);
   G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
   G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
   deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);
   Q = ((deriver >> 24) & 0xff);
   G2 = ((Q << 1) ^ ((Q & 0x80) != 0 ? (uint)0x14D : 0)) & 0xff;
   G3 = ((Q >> 1) ^ ((Q & 0x01) != 0 ? ((uint)0x14D >> 1) : 0)) ^ G2;
   deriver = ((deriver << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ Q);

   uint key = deriver;

   byte[] input = BitConverter.GetBytes(input_u);

   const int R = 16;
   const int W = 32;
   UInt32[] KEYS = new UInt32[2 * R + 4];
   int nLgw = (int)(Math.Log((double)W) / Math.Log(2.0));

   /* Generate keys Uint32[] */
   //UInt32 P32 = 0xB7E15163;
   //UInt32 Q32 = 0x9E3779B9;
   UInt32 F, A, B;
   UInt32 dwByteOne, dwByteTwo, dwByteThree, dwByteFour;
   dwByteOne = key >> 24;
   dwByteTwo = key >> 8;
   dwByteTwo = dwByteTwo & 0x0010;
   dwByteThree = key << 8;
   dwByteThree = dwByteThree & 0x0100;
   dwByteFour = key << 24;
   key = dwByteOne | dwByteTwo | dwByteThree | dwByteFour;
   KEYS[0] = P32;
   for (F = 1; F < 2 * R + 4; F++)
   {
    KEYS[F] = KEYS[F - 1] + Q32;
   }
   F = A = B = 0;
   int v = 3 * Math.Max(1, 2 * R + 4);
   for (int s = 1; s <= v; s++)
   {
    int c = 3;
    c = c << (W - nLgw);
    c = c >> (W - nLgw);
    A = KEYS[F] = KEYS[F] + A + B << c | KEYS[F] + A + B >> W - c;
    int p = (int)(A + B);
    int nRgw = (int)(Math.Log((double)W) / Math.Log(2.0));
    p = p << (W - nRgw);
    p = p >> (W - nRgw);
    B = key = key + A + B << p | key + A + B >> W - p;
    F = (F + 1) % (2 * R + 4);
   }
   /* ---------------------------------------------------------------------- */
   UInt32[] pdwTemp = null;
   for (int i = 0; i < input.Length; i += 16)
   {
    pdwTemp = ConvertFromByteArrayToUIn32(input, i);
    pdwTemp[0] = (pdwTemp[0] - KEYS[2 * R + 2]);
    pdwTemp[2] = (pdwTemp[2] - KEYS[2 * R + 3]);
    for (int j = R; j >= 1; j--)
    {
     UInt32 temp = pdwTemp[3];
     pdwTemp[3] = pdwTemp[2];
     pdwTemp[2] = pdwTemp[1];
     pdwTemp[1] = pdwTemp[0];
     pdwTemp[0] = temp;
     UInt32 t = LeftShift(W, (pdwTemp[1] * (2 * pdwTemp[1] + 1)),
                         OffsetAmount(W, (int)(Math.Log((double)W) / Math.Log(2.0))));
     UInt32 u = LeftShift(W, (pdwTemp[3] * (2 * pdwTemp[3] + 1)),
                         OffsetAmount(W, (int)(Math.Log((double)W) / Math.Log(2.0))));
     pdwTemp[0] = (RightShift(W, (pdwTemp[0] - KEYS[2 * j]), OffsetAmount(W, (int)u))) ^ t;
     pdwTemp[2] = (RightShift(W, (pdwTemp[2] - KEYS[2 * j + 1]), OffsetAmount(W, (int)t))) ^ u;
    }
    pdwTemp[1] = (pdwTemp[1] - KEYS[0]);
    pdwTemp[3] = (pdwTemp[3] - KEYS[1]);
   }

   byte[] result_b = ConvertFromUInt32ToByteArray(pdwTemp);

   string result_str = String.Empty;
   int key_num = new Random().Next(0, int.MaxValue) ^ 0x7C9 >> (input.Length % 4) | 256;
   foreach (var b in result_b)
   {
    int num0 = (key_num ^ (int)(byte)b);
    string c = "{" + (num0) + "}";
    result_str += c;
   }
   result_str += "{" + key_num + "}";
   return result_str;
  }

  #region Encryption helpers

  public byte[] ConvertFromUInt32ToByteArray(UInt32[] array)
  {
   List<byte> results = new List<byte>();
   foreach (UInt32 value in array)
   {
    byte[] converted = BitConverter.GetBytes(value);
    results.AddRange(converted);
   }
   return results.ToArray();
  }

  public UInt32[] ConvertFromByteArrayToUIn32(byte[] array, int position)
  {
   List<UInt32> results = new List<UInt32>();
   int length = position + 16;
   for (int i = position; i < length; i += 4)
   {
    byte[] temp = new byte[4];

    for (int j = 0; j < 4; ++j)
    {
     if (i + j < array.Length)
      temp[j] = array[i + j];
     else
      temp[j] = 0x00;
    }
    results.Add(BitConverter.ToUInt32(temp, 0));
   }
   return results.ToArray();
  }

  public UInt32 RightShift(int W, UInt32 z_value, int z_shift)
  {
   return ((z_value >> z_shift) | (z_value << (W - z_shift)));
  }

  public UInt32 LeftShift(int W, UInt32 z_value, int z_shift)
  {
   return ((z_value << z_shift) | (z_value >> (W - z_shift)));
  }

  public int OffsetAmount(int W, int dwVar)
  {
   int nLgw = (int)(Math.Log((double)W) / Math.Log(2.0));

   dwVar = dwVar << (W - nLgw);
   dwVar = dwVar >> (W - nLgw);

   return dwVar;
  }

  #endregion
 }
 class ProtectionContext
 {
  public Context ctx;
  public MethodDef DecryptionMethod;
  public List<string> UsedKeys = new List<string>();
  public RC6LiteEncryption Encryptor;
  public Encryption Encryption;

  public void GetDecryptionMethod()
  {
   var assembly = AssemblyDef.Load("Confuser.Runtime.dll");
   var type = assembly.ManifestModule.Find("Confuser.Runtime.Constant_Two", false);
   var method = type.FindMethod("BigNumberDecoder");
   method.DeclaringType = ctx.CurrentModule.GlobalType;
   method.Name = ctx.generator.GenerateNewName();
   DecryptionMethod = method;
  }

 }
 class Encryption
 {
  public ProtectionContext pCtx;
  public Context ctx;
  public void EncryptUint(int CurrentPos, MethodDef method, Instruction ins, MethodDef Decryption)
  {
   //int algo_key = Math.Abs(ctx.generator.RandomInt());
   int P32 = Math.Abs(ctx.generator.RandomInt());
   int Q32 = Math.Abs(ctx.generator.RandomInt());

   var EncryptedOperrand = pCtx.Encryptor.Encrypt(int.Parse(ins.Operand.ToString()), (uint)P32, (uint)Q32);

   ins.OpCode = OpCodes.Ldstr;
   ins.Operand = EncryptedOperrand;

   method.Body.Instructions.Insert(CurrentPos + 1, new Instruction(OpCodes.Ldc_I4, P32));
   method.Body.Instructions.Insert(CurrentPos + 2, new Instruction(OpCodes.Ldc_I4, Q32));
   method.Body.Instructions.Insert(CurrentPos + 3, new Instruction(OpCodes.Call, Decryption));
   pCtx.UsedKeys.Add(P32.ToString());
   pCtx.UsedKeys.Add(Q32.ToString());


  }
 }

 class BigNumberProtect : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Encrypt all Uints to hardcoded string using algo RC6 Modded so far!";
  public override string Id => Author + "BigNumberProtect";
  public override string Name => "BigNumberProtect";

  public MethodDef DecryptionMethodResources;

  public override void Execute(Context ctx)
  {
   var pCtx = new ProtectionContext();
   pCtx.ctx = ctx;
   pCtx.GetDecryptionMethod();
   pCtx.Encryptor = new RC6LiteEncryption();
   pCtx.Encryption = new Encryption();
   pCtx.Encryption.ctx = ctx;
   pCtx.Encryption.pCtx = pCtx;

   GetDecryptionMethodRes(ctx);

   foreach (var m in ctx.analyzer.targetCtx.methods_usercode)
   {
    DoEncrypt(pCtx, ctx, m);
    DoEncryptSpecified(m, ctx, pCtx.UsedKeys);
   }


   ProtectRuntimeMethodRes(pCtx);

   #region OldStuff

   ////ldc.i4.1
   //for (int i = 0; i < insCnt; i++)
   //{

   // Instruction ins = method.Body.Instructions[i];

   // if (ins.Operand == null) continue;

   // if (ins.OpCode == OpCodes.Ldc_I4_1 && !pCtx.UsedKeys.Contains(ins.Operand.ToString()) && ins.OpCode != null)
   // {
   //  MethodDef DecMethod = pCtx.DecryptionMethod;

   //  pCtx.Encryption.EncryptUint(i, method, ins, DecMethod); //Encrypt number
   // }
   //}

   ////ldc.i4.s
   //for (int i = 0; i < insCnt; i++)
   //{

   // Instruction ins = method.Body.Instructions[i];

   // if (ins.Operand == null) continue;

   // if (ins.OpCode == OpCodes.Ldc_I4_S && !pCtx.UsedKeys.Contains(ins.Operand.ToString()) && ins.OpCode != null)
   // {
   //  MethodDef DecMethod = pCtx.DecryptionMethod;

   //  pCtx.Encryption.EncryptUint(i, method, ins, DecMethod); //Encrypt number
   // }
   //}
   #endregion

  }

  public void GetDecryptionMethodRes(Context ctx)
  {
   var assembly = AssemblyDef.Load("Confuser.Runtime.dll");
   var type = assembly.ManifestModule.Find("Confuser.Runtime.KeysHiderRuntime", false);
   var method = type.FindMethod("GetKey");
   method.DeclaringType = ctx.CurrentModule.GlobalType;
   method.Name = ctx.generator.GenerateNewName();
   DecryptionMethodResources = method;
  }

  public void DoEncryptSpecified(MethodDef method, Context ctx, List<string> usedKeys)
  {
   int insCnt = method.Body.Instructions.Count;

   for (int i = 0; i < insCnt; i++)
   {
    Instruction ins = method.Body.Instructions[i];
    if (ins.OpCode == OpCodes.Ldc_I4 && usedKeys.Contains(ins.Operand.ToString()))
    {
     var num = int.Parse(ins.Operand.ToString());
     Encode(ctx, i, method, ins, DecryptionMethodResources);
    }
   }
  }

  public void Encode(Context ctx, int CurrentPos, MethodDef method, Instruction ins, MethodDef TargetMethod)
  {

   int number = int.Parse(ins.Operand.ToString());

   /* Simple encoding */
   byte[] plain_num = BitConverter.GetBytes(number);
   byte[] bytes = SHA1.Create().ComputeHash(BitConverter.GetBytes(1993));
   for (int i = 0; i <= ((plain_num.Length * 2) + bytes.Length); i++)
   {
    plain_num[i % plain_num.Length] = (byte)(((byte)((plain_num[i % plain_num.Length] + plain_num[(i + 1) % plain_num.Length]) % 0x100)) ^ bytes[i % bytes.Length]);
   }
   string encoded = Convert.ToBase64String(plain_num);
   var res_name = ctx.generator.GenerateNewName();
   /* --------------------------------------------------- */

   byte[] resourceData = Encoding.UTF8.GetBytes(encoded);
   ctx.CurrentModule.Resources.Add(new EmbeddedResource(res_name, resourceData,
       ManifestResourceAttributes.Private));

   ins.OpCode = OpCodes.Ldstr;
   ins.Operand = res_name;

   //method.Body.Instructions.Insert(CurrentPos + 1, new Instruction(OpCodes.Ldstr, res_name));
   method.Body.Instructions.Insert(CurrentPos + 1, new Instruction(OpCodes.Call, TargetMethod));

  }

  public void DoEncrypt(ProtectionContext pCtx, Context ctx, MethodDef method)
  {
   int insCnt = method.Body.Instructions.Count;

   for (int i = 0; i < insCnt; i++)
   {
    Instruction ins = method.Body.Instructions[i];
    if (ins.OpCode == OpCodes.Ldc_I4 && !pCtx.UsedKeys.Contains(ins.Operand.ToString()))
    {
     MethodDef DecMethod = pCtx.DecryptionMethod;

     pCtx.Encryption.EncryptUint(i, method, ins, DecMethod); //Encrypt number
    }
   }
  }

  public void ProtectRuntimeMethodRes(ProtectionContext pCtx)
  {
   pCtx.ctx.runtime_protect.runtime_refproxy2.DoRefProxy2(DecryptionMethodResources, pCtx.ctx);
  }

 }
}

class BigNumberRuntimeProtection
{
 public void DoProtect(Context ctx, MethodDef method)
 {
  var pCtx = new ProtectionContext();
  pCtx.ctx = ctx;
  pCtx.GetDecryptionMethod();
  pCtx.Encryptor = new RC6LiteEncryption();
  pCtx.Encryption = new Encryption();
  pCtx.Encryption.ctx = ctx;
  pCtx.Encryption.pCtx = pCtx;

  var p = new BigNumberProtect();

  p.DoEncrypt(pCtx, ctx, method);

 }

}
