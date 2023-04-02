using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Eddy_Protector.Protections.StringEncrypt
{
 class StringEncryptProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Encrypt all strings and number in assembly, supports LDCi4 , and LDSTR";
  public override string Id => Author + ".StringEncrypt";
  public override string Name => "StringEncrypt";

  public ConstantContext context;

  public override void Execute(Context ctx)
  {
   context = new ConstantContext();
   context.Encrypt = new Encryption();
   context.Encrypt.ctx = context;
   context.context = ctx;

   //Decryption methods
   context.LDCI4Decrypt_m = context.GetDecryptionMethod("RSADecryptLDCI4", "ldci4");
   context.LDSTRDecrypt_m = context.GetDecryptionMethod("XXTEADecryptSTR", "ldstr");
   context.LDCI4Decrypt_m.DeclaringType = ctx.CurrentModule.GlobalType;
   context.LDSTRDecrypt_m.DeclaringType = ctx.CurrentModule.GlobalType;

   foreach (MethodDef method in ctx.analyzer.targetCtx.methods_usercode)
   {

    ctx.logger.Progress(String.Format("Processing method: {0}", method.Name));

    if (!method.HasBody) { return; }

    //for(int a = 0; a < 2;a++)
    //{
     DoEncrypt(context, method);
    //}
    

   }

   ProtectRuntimeMethods(context);
  }

  public void ProtectRuntimeMethods(ConstantContext ctx)
  {
   var control = ctx.context.runtime_protect.runtime_controlflow1;
   var mutate = ctx.context.runtime_protect.runtime_mutation;
   var refProxy = ctx.context.runtime_protect.runtime_refproxy2;
   var keysHider = ctx.context.runtime_protect.runtime_keyshider;

   var decLdstr = ctx.LDSTRDecrypt_m;
   var decLdci4 = ctx.LDCI4Decrypt_m;
   var rtmethods = ctx.context.runtime_protect.runtime_methods;

   /* Protect runtime methods */
   mutate.DoMutation(decLdstr, ctx.context);
   control.DoControlFlow(decLdstr, ctx.context);
   refProxy.DoRefProxy2(decLdstr, ctx.context);

   mutate.DoMutation(decLdci4, ctx.context);
   control.DoControlFlow(decLdci4, ctx.context);
   refProxy.DoRefProxy2(decLdci4, ctx.context);

   /* Add to list */
   rtmethods.Add(decLdci4);
   rtmethods.Add(decLdstr);

   ctx.context.analyzer.targetCtx.methods_virtualize.Add(decLdci4);
   //ctx.context.analyzer.targetCtx.methods_virtualize.Add(decLdstr);


  }

  public void DoEncrypt(ConstantContext context, MethodDef method)
  {
   int insCnt = method.Body.Instructions.Count;




   for (int i = 0; i < insCnt; i++)
   {
    Instruction ins = method.Body.Instructions[i];
    if (ins.OpCode == OpCodes.Ldc_I4/* && !context.UsedKeysLdci4.Contains(ins.Operand.ToString())*/)
    {
     MethodDef DecMethod = context.LDCI4Decrypt_m;

     //InjectHelper.Inject(method, context.context.moduleDef);

     context.Encrypt.EncryptLDCI4(i, method, ins, DecMethod); //Encrypt number
    }
   }

   for (int i = 0; i < insCnt; i++)
   {
    Instruction ins = method.Body.Instructions[i];
    if (ins.OpCode == OpCodes.Ldstr /*&& !context.UsedKeysLdstr.Contains(ins.Operand.ToString())*/)
    {
     MethodDef DecMethod = context.LDSTRDecrypt_m;

     //InjectHelper.Inject(method, context.context.moduleDef);

     context.Encrypt.EncryptLDSTR(i, method, ins, DecMethod);
    }
   }





  }


  #region notused

  //public void EncryptLDSTR(ConstantContext context, MethodDef method)
  //{
  //	int insCnt = method.Body.Instructions.Count;
  //	for (int i = 0; i < insCnt; i++)
  //	{
  //		Instruction ins = method.Body.Instructions[i];

  //		if (ins.OpCode == OpCodes.Ldstr/* && !context.UsedKeysLdci4.Contains(ins.Operand.ToString()) && !context.UsedKeysLdci4.Contains(ins.Operand.ToString())*/)
  //		{
  //			MethodDef DecMethod = context.LDSTRDecrypt_m;

  //			//InjectHelper.Inject(method, context.context.moduleDef);

  //			context.Encrypt.EncryptLDSTR(i, method, ins, DecMethod);
  //		}
  //	}
  //}

  //public void EncryptLDCI4(ConstantContext context, MethodDef method)
  //{

  //	int insCnt = method.Body.Instructions.Count;

  //	for (int i = 0; i < insCnt; i++)
  //	{
  //		Instruction ins = method.Body.Instructions[i];
  //		if (ins.OpCode == OpCodes.Ldc_I4/* && !context.UsedKeysLdci4.Contains(ins.Operand.ToString()) && !context.UsedKeysLdci4.Contains(ins.Operand.ToString())*/)
  //		{
  //			MethodDef DecMethod = context.LDCI4Decrypt_m;

  //			//InjectHelper.Inject(method, context.context.moduleDef);

  //			context.Encrypt.EncryptLDCI4(i, method, ins, DecMethod); //Encrypt number
  //		}
  //	}
  //}

  #endregion

 }

 class RuntimeStrinEcryption
 {

  public ConstantContext context;


  public void DoEncryption(MethodDef method, Context ctx)
  {
   context = new ConstantContext();
   context.Encrypt = new Encryption();
   context.protection = new StringEncryptProtection();
   context.Encrypt.ctx = context;
   context.context = ctx;

   //Decryption methods
   context.LDCI4Decrypt_m = context.GetDecryptionMethod("RSADecryptLDCI4", "ldci4");
   context.LDSTRDecrypt_m = context.GetDecryptionMethod("XXTEADecryptSTR", "ldstr");
   context.LDCI4Decrypt_m.DeclaringType = ctx.CurrentModule.GlobalType;
   context.LDSTRDecrypt_m.DeclaringType = ctx.CurrentModule.GlobalType;

   context.LDCI4Decrypt_m.DeclaringType = ctx.CurrentModule.GlobalType;
   context.LDSTRDecrypt_m.DeclaringType = ctx.CurrentModule.GlobalType;

   var p = context.protection;

   if (!method.HasBody) { return; }

   for (int a = 0; a < 1; a++)
   {
    p.DoEncrypt(context, method);
   }
   p.ProtectRuntimeMethods(context);
  }
 }
}
