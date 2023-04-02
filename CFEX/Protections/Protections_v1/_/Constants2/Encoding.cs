using Eddy_Protector.Core;
using Eddy_Protector.Core.Poly;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace Eddy_Protector.Protections.Constants2
{

 class Encoding
 {

  ModuleDefinition mod;
  Cyphering cyphering;


  public void Initialize3(ModuleDefinition mod, Context ctx)
  {
   this.mod = mod;
   cyphering = new Cyphering();
  }

  
  public void Encrypt(ProtectionContext pContext, Dictionary<ModuleDefinition, ProtectionContext> Decoders)
  {
   pContext = Decoders[mod];

   //byte[] final;

   MemoryStream str = new MemoryStream();
   using (BinaryWriter wtr = new BinaryWriter(str))
    foreach (byte[] dat in pContext.dats)
     wtr.Write(dat);
   byte[] buff = cyphering.XorCrypt(str.ToArray(), pContext.key);

   if (pContext.isDyn /*|| txt.isNative*/)
   {
    byte[] e = cyphering.Encrypt(buff, pContext.exp);

    int dictionary = 1 << 23;

    Int32 posStateBits = 2;
    Int32 litContextBits = 3; // for normal files
                              // UInt32 litContextBits = 0; // for 32-bit data
    Int32 litPosBits = 0;
    // UInt32 litPosBits = 2; // for 32-bit data
    Int32 algorithm = 2;
    Int32 numFastBytes = 128;
    string mf = "bt4";

    SevenZip.CoderPropID[] propIDs =
       {
         SevenZip.CoderPropID.DictionarySize,
         SevenZip.CoderPropID.PosStateBits,
         SevenZip.CoderPropID.LitContextBits,
         SevenZip.CoderPropID.LitPosBits,
         SevenZip.CoderPropID.Algorithm,
         SevenZip.CoderPropID.NumFastBytes,
         SevenZip.CoderPropID.MatchFinder,
         SevenZip.CoderPropID.EndMarker
        };
    object[] properties =
       {
         (int)dictionary,
         (int)posStateBits,
         (int)litContextBits,
         (int)litPosBits,
         (int)algorithm,
         (int)numFastBytes,
         mf,
         false
        };

    MemoryStream x = new MemoryStream();
    var encoder = new SevenZip.Compression.LZMA.Encoder();
    encoder.SetCoderProperties(propIDs, properties);
    encoder.WriteCoderProperties(x);
    Int64 fileSize;
    //MemoryStream output = new MemoryStream();
    fileSize = e.Length;
    for (int i = 0; i < 8; i++)
     x.WriteByte((Byte)(fileSize >> (8 * i)));
    encoder.Code(new MemoryStream(e), x, -1, -1, null);


    //using (var s = new CryptoStream(output,
    //    new RijndaelManaged().CreateEncryptor(pContext.keyBuff, MD5.Create().ComputeHash(pContext.keyBuff))
    //    , CryptoStreamMode.Write))
    // s.Write(x.ToArray(), 0, (int)x.Length);

    //final = output.ToArray();

    var pwd = string.Join("", SHA512.Create().ComputeHash(System.Text.Encoding.ASCII.GetBytes("Eddy^CZ")).Select(f => f.ToString("x2")));

    byte[] enc = Encrypt(x.ToArray(), pwd);


    mod.Resources.Add(new EmbeddedResource(pContext.resId, ManifestResourceAttributes.Private, enc));

   }

   #region NotUsed
   //else
   //{
   // int dictionary = 1 << 23;

   // Int32 posStateBits = 2;
   // Int32 litContextBits = 3; // for normal files
   //                           // UInt32 litContextBits = 0; // for 32-bit data
   // Int32 litPosBits = 0;
   // // UInt32 litPosBits = 2; // for 32-bit data
   // Int32 algorithm = 2;
   // Int32 numFastBytes = 128;
   // string mf = "bt4";

   // SevenZip.CoderPropID[] propIDs =
   //    {
   //      SevenZip.CoderPropID.DictionarySize,
   //      SevenZip.CoderPropID.PosStateBits,
   //      SevenZip.CoderPropID.LitContextBits,
   //      SevenZip.CoderPropID.LitPosBits,
   //      SevenZip.CoderPropID.Algorithm,
   //      SevenZip.CoderPropID.NumFastBytes,
   //      SevenZip.CoderPropID.MatchFinder,
   //      SevenZip.CoderPropID.EndMarker
   //     };
   // object[] properties =
   //    {
   //      (int)dictionary,
   //      (int)posStateBits,
   //      (int)litContextBits,
   //      (int)litPosBits,
   //      (int)algorithm,
   //      (int)numFastBytes,
   //      mf,
   //      false
   //     };

   // MemoryStream x = new MemoryStream();
   // var encoder = new SevenZip.Compression.LZMA.Encoder();
   // encoder.SetCoderProperties(propIDs, properties);
   // encoder.WriteCoderProperties(x);
   // Int64 fileSize;
   // fileSize = buff.Length;
   // for (int i = 0; i < 8; i++)
   //  x.WriteByte((Byte)(fileSize >> (8 * i)));
   // encoder.Code(new MemoryStream(buff), x, -1, -1, null);

   // MemoryStream output = new MemoryStream();
   // using (var s = new CryptoStream(output,
   //     new RijndaelManaged().CreateEncryptor(txt.keyBuff, MD5.Create().ComputeHash(txt.keyBuff))
   //     , CryptoStreamMode.Write))
   //  s.Write(x.ToArray(), 0, (int)x.Length);

   // final = cyphering.EncryptSafe(output.ToArray(), BitConverter.ToUInt32(txt.keyBuff, 0xc) * (uint)txt.resKey);
   //}
   #endregion


   
  }

  /* PolyStairs Encryption */
  public byte[] Encrypt(byte[] byte_0, string string_0)
  {
   byte[] bytes = System.Text.Encoding.ASCII.GetBytes(string_0);
   for (int i = 0; i <= ((byte_0.Length * 2) + bytes.Length); i++)
   {
    byte_0[i % byte_0.Length] = (byte)(((byte)((byte_0[i % byte_0.Length] + byte_0[(i + 1) % byte_0.Length]) % 0x100)) ^ bytes[i % bytes.Length]);
   }
   return byte_0;
  }

  bool IsNull(object obj)
  {
   if (obj is int)
    return (int)obj == 0;
   else if (obj is long)
    return (long)obj == 0;
   else if (obj is float)
    return (float)obj == 0;
   else if (obj is double)
    return (double)obj == 0;
   else if (obj is string)
    return string.IsNullOrEmpty((string)obj);
   else
    return true;
  }
  void ExtractData(List<ConstantContext> txts, ProtectionContext txt, Context ctx, Dictionary<ModuleDefinition, ProtectionContext> Decoders)
  {
   foreach (var mtd in ctx.analyzer.targetCtx.targets_mono)
   {

    if (mtd.DeclaringType == mod.GetType("<Module>")) continue;

    ///MethodDefinition mtd = tuple.Item1 as MethodDefinition;
    if (Decoders[mod].consters.Any(_ => _.conster == mtd) || !mtd.HasBody) continue;
    var bdy = mtd.Body;
    var insts = bdy.Instructions;
    ILProcessor psr = bdy.GetILProcessor();
    for (int i = 0; i < insts.Count; i++)
    {
     if (insts[i].OpCode.Code == Code.Ldstr ||
         (true && (insts[i].OpCode.Code == Code.Ldc_I4 ||
         insts[i].OpCode.Code == Code.Ldc_I8 ||
         insts[i].OpCode.Code == Code.Ldc_R4 ||
         insts[i].OpCode.Code == Code.Ldc_R8)))
     {
      txts.Add(new ConstantContext()
      {
       mtd = mtd,
       psr = psr,
       str = insts[i],
       a = (uint)new Random().Next(),
       conster = txt.consters[new Random().Next(0, txt.consters.Length)]
      });
     }
    }
   }
  }

  //foreach (var tuple in mtds)
  //{
  // MethodDefinition mtd = tuple.Item1 as MethodDefinition;
  // if (cc.txts[mod].consters.Any(_ => _.conster == mtd) || !mtd.HasBody) continue;
  // var bdy = mtd.Body;
  // var insts = bdy.Instructions;
  // ILProcessor psr = bdy.GetILProcessor();
  // for (int i = 0; i < insts.Count; i++)
  // {
  //  if (insts[i].OpCode.Code == Code.Ldstr ||
  //      (true && (insts[i].OpCode.Code == Code.Ldc_I4 ||
  //      insts[i].OpCode.Code == Code.Ldc_I8 ||
  //      insts[i].OpCode.Code == Code.Ldc_R4 ||
  //      insts[i].OpCode.Code == Code.Ldc_R8)))
  //  {
  //   txts.Add(new Context()
  //   {
  //    mtd = mtd,
  //    psr = psr,
  //    str = insts[i],
  //    a = (uint)new Random().Next(),
  //    conster = txt.consters[new Random().Next(0, txt.consters.Length)]
  //   });
  //  }
  // }
  //}

  byte[] GetOperand(object operand)
  {
   byte[] ret;
   if (operand is double)
    ret = BitConverter.GetBytes((double)operand);
   else if (operand is float)
    ret = BitConverter.GetBytes((float)operand);
   else if (operand is int)
    ret = BitConverter.GetBytes((int)operand);
   else if (operand is long)
    ret = BitConverter.GetBytes((long)operand);
   else
    ret = System.Text.Encoding.UTF8.GetBytes((string)operand);
   return ret;
  }
  uint GetOperandLen(object operand)
  {
   if (operand is double) return 8;
   else if (operand is float) return 4;
   else if (operand is int) return 4;
   else if (operand is long) return 8;
   else return (uint)System.Text.Encoding.UTF8.GetByteCount(operand as string);
  }
  bool IsEqual(byte[] a, byte[] b)
  {
   int l = Math.Min(a.Length, b.Length);
   for (int i = 0; i < l; i++)
    if (a[i] != b[i]) return false;
   return true;
  }
  void FinalizeBodies(List<ConstantContext> txts)
  {
   double total = txts.Count;
   int interval = 1;
   if (total > 1000)
    interval = (int)total / 100;

   for (int i = 0; i < txts.Count; i++)
   {
    int idx = txts[i].mtd.Body.Instructions.IndexOf(txts[i].str);
    Instruction now = txts[i].str;
    if (IsNull(now.Operand)) continue;

    TypeReference typeRef;
    if (now.Operand is int)
     typeRef = txts[i].mtd.Module.TypeSystem.Int32;
    else if (now.Operand is long)
     typeRef = txts[i].mtd.Module.TypeSystem.Int64;
    else if (now.Operand is float)
     typeRef = txts[i].mtd.Module.TypeSystem.Single;
    else if (now.Operand is double)
     typeRef = txts[i].mtd.Module.TypeSystem.Double;
    else
     typeRef = txts[i].mtd.Module.TypeSystem.String;
    Instruction call = Instruction.Create(OpCodes.Call, new GenericInstanceMethod(txts[i].conster.conster)
    {
     GenericArguments = { typeRef }
    });
    call.SequencePoint = now.SequencePoint;

    txts[i].psr.InsertAfter(idx, call);
    txts[i].psr.Replace(idx, Instruction.Create(OpCodes.Ldc_I4, (int)txts[i].a));
    txts[i].psr.InsertAfter(idx, Instruction.Create(OpCodes.Ldc_I8, (long)txts[i].b));

    //if (i % interval == 0 || i == txts.Count - 1)
    // progresser.SetProgress(i + 1, txts.Count);
   }

   List<int> hashs = new List<int>();
   for (int i = 0; i < txts.Count; i++)
   {
    if (hashs.IndexOf(txts[i].mtd.GetHashCode()) == -1)
    {
     txts[i].mtd.Body.MaxStackSize += 2;
     hashs.Add(txts[i].mtd.GetHashCode());
    }
   }
  }


  public void ProcessModule(Context ctx, ProtectionContext pContext , Dictionary<ModuleDefinition, ProtectionContext> Decoders)
  {
   pContext = Decoders[mod];

   foreach (var i in pContext.consters)
   {
    i.keyInst.OpCode = OpCodes.Ldc_I4;
    i.keyInst.Operand = (int)(pContext.key ^ 512);
   }

   List<ConstantContext> txts = new List<ConstantContext>();

   ExtractData(txts, pContext, ctx , Decoders);

   pContext.dict.Clear();

   for (int i = 0; i < txts.Count; i++)
   {
    object val = txts[i].str.Operand as object;
    if (IsNull(val)) continue;

    uint x = 512 * txts[i].a;


    ulong hash = cyphering.ComputeHash(x,
                (uint)txts[i].conster.key3,
                (ulong)txts[i].conster.key0,
                (ulong)txts[i].conster.key1,
                (ulong)txts[i].conster.key2);
    uint idx, len;
    if (pContext.dict.ContainsKey(val))
     txts[i].b = cyphering.Combine(idx = (uint)pContext.dict[val], len = GetOperandLen(val)) ^ hash;
    else
    {
     byte[] dat = GetOperand(val);
     txts[i].b = cyphering.Combine(idx = (uint)pContext.idx, len = (uint)dat.Length) ^ hash;

     pContext.dats.Add(dat);
     pContext.dict[val] = pContext.idx;

     pContext.idx += dat.Length;
    }
   }

   FinalizeBodies(txts);
  }
 }
}

