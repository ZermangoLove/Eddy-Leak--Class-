using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace Eddy_Protector.Protections.KeysHider
{
 class KeysHiderProtection : ProtectionPhase
 {
  public override string Author => "";
  public override string Description => "";
  public override string Id => "";
  public override string Name => "";

  public Context Context;
  public MethodDef DecryptionMethod;

  public override void Execute(Context ctx)
  {

   Context = ctx;
   GetDecryptionMethod();
   

   foreach (var m in ctx.analyzer.targetCtx.methods_usercode)
   {
    DoEncrypt(m, ctx);
   }
  }

  public void GetDecryptionMethod()
  {
   var assembly = AssemblyDef.Load("Confuser.Runtime.dll");
   var type = assembly.ManifestModule.Find("Confuser.Runtime.KeysHiderRuntime", false);
   var method = type.FindMethod("GetKey");
   method.DeclaringType = Context.CurrentModule.GlobalType;
   method.Name = Context.generator.GenerateNewName();
   DecryptionMethod = method;
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
     Encode(ctx,i, method, ins, DecryptionMethod);
    }
   }
  }

  public void DoEncrypt(MethodDef method, Context ctx)
  {

   int insCnt = method.Body.Instructions.Count;

   for (int i = 0; i < insCnt; i++)
   {
    Instruction ins = method.Body.Instructions[i];
    if (ins.OpCode == OpCodes.Ldc_I4)
    {
     var num = int.Parse(ins.Operand.ToString());
     Encode(ctx,i, method,ins,DecryptionMethod);
    }
   }

   for (int i = 0; i < insCnt; i++)
   {
    Instruction ins = method.Body.Instructions[i];
    if (ins.OpCode == OpCodes.Ldc_I4_S)
    {
     var num = int.Parse(ins.Operand.ToString());
     Encode(ctx,i, method, ins, DecryptionMethod);
    }
   }

  }

  public void Encode(Context ctx,int CurrentPos, MethodDef method, Instruction ins, MethodDef TargetMethod)
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
   var res_name = ctx.generator.RandomUlong().ToString();
   /* --------------------------------------------------- */

   byte[] resourceData = Encoding.UTF8.GetBytes(encoded);
   ctx.CurrentModule.Resources.Add(new EmbeddedResource(res_name, resourceData,
       ManifestResourceAttributes.Private));

   ins.OpCode = OpCodes.Ldstr;
   ins.Operand = res_name;

   //method.Body.Instructions.Insert(CurrentPos + 1, new Instruction(OpCodes.Ldstr, res_name));
   method.Body.Instructions.Insert(CurrentPos + 1, new Instruction(OpCodes.Call, TargetMethod));

  }

  public void ProtectRuntime()
  {
   Context.runtime_protect.runtime_controlflow1.DoControlFlow(DecryptionMethod, Context);

   Context.runtime_protect.runtime_refproxy2.DoRefProxy2(DecryptionMethod, Context);

   Context.runtime_protect.runtime_intmath.DoIntMath(DecryptionMethod, Context);
  }

 }

 class RuntimeKeysHider
 {


  public void DoKeysHideSpecified(MethodDef method, Context ctx, List<string> usedKeys)
  {
   var p = new KeysHiderProtection();
   p.Context = ctx;

   p.GetDecryptionMethod();
   p.DoEncryptSpecified(method, ctx,usedKeys);
   p.ProtectRuntime();
  }

  public void DoKeysHide(MethodDef method, Context ctx)
  {

   var p = new KeysHiderProtection();
   p.Context = ctx;

   p.GetDecryptionMethod();
   p.DoEncrypt(method, ctx);
   p.ProtectRuntime();
  }
 }
}
