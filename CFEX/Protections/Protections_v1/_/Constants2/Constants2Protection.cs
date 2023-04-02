using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;

using Mono.Cecil;
using Eddy_Protector.Core.Poly;
using Eddy_Protector.Core.Poly.Visitors;
using Eddy_Protector.Core.OldConfuser;
using Mono.Cecil.Cil;
using System.IO;
using Mono.Cecil.Metadata;
using dnlib.DotNet;

namespace Eddy_Protector.Protections.Constants2
{
 class Constants2Protection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Aditional constants protection from old Confuser";
  public override string Id => Author+".Constants2";
  public override string Name => "Constants2";

  //Constants2Protection cc;
  public Dictionary<ModuleDefinition, ProtectionContext> Decoders = new Dictionary<ModuleDefinition, ProtectionContext>();
  ModuleDefinition mod;
  //RuntimeHelper _Helpers;
  Context ctx_;
  public ProtectionContext pContext;

  public override void Execute(Context ctx)
  {

   for(int a = 0; a < 2; a++)
   {
    DoConstantEncrypt(ctx);
   }
   

   ctx.analyzer.targetCtx.Module_mono = mod; //Load protected assembly to buffer

   #region NotUsed

   //FileStream output = File.Open("aaa.exe", FileMode.Create);

   //foreach (var typ in mod.GetAllTypes())
   //{

   //}

   //MetadataProcessor psr = new MetadataProcessor();

   //psr.Process(mod, output, new WriterParameters());

   //mod.Write(mem);

   //output.CopyTo(mem);

   #endregion




  }

  public void DoConstantEncrypt(Context ctx)
  {
   ctx_ = ctx;
   pContext = new ProtectionContext();
   mod = ctx.analyzer.targetCtx.Module_mono;

   Decoders[mod] = new ProtectionContext();
   Decoders[mod].dats = new List<byte[]>();
   Decoders[mod].idx = 0;
   Decoders[mod].dict = new Dictionary<object, int>();

   FirstPhase(ctx);

   Encoding encoding = new Encoding();
   encoding.Initialize3(mod, ctx);
   encoding.ProcessModule(ctx, pContext, Decoders);
   encoding.Encrypt(pContext, Decoders);
  }


  public void FirstPhase(Context ctx)
  {

   pContext = Decoders[mod];

   pContext.isDyn = true;
   TypeDefinition modType = mod.GetType("<Module>");
   FieldDefinition constTbl = new FieldDefinition(ctx.generator.GenerateNewName(), Mono.Cecil.FieldAttributes.Static | Mono.Cecil.FieldAttributes.CompilerControlled, mod.Import(typeof(Dictionary<uint, object>)));
   modType.Fields.Add(constTbl);
   FieldDefinition constBuffer = new FieldDefinition(ctx.generator.GenerateNewName(), Mono.Cecil.FieldAttributes.Static | Mono.Cecil.FieldAttributes.CompilerControlled, mod.Import(typeof(byte[])));
   modType.Fields.Add(constBuffer);

   var expGen = new ExpressionGenerator(new Random().Next());

   int seed = expGen.Seed;

   pContext.exp = expGen.Generate(10);
   pContext.invExp = ExpressionInverser.InverseExpression(pContext.exp);
   pContext.consters = CreateConsters(pContext, new Random(), "Initialize", constTbl, constBuffer);
  }

  Conster[] CreateConsters(ProtectionContext txt, Random rand, string injectName,
                         FieldDefinition constTbl, FieldDefinition constBuffer)
  {
   AssemblyDefinition injection = AssemblyDefinition.ReadAssembly(typeof(Iid).Assembly.Location);
   injection.MainModule.ReadSymbols();
   MethodDefinition DecoderMethod = injection.MainModule.GetType("Encryptions").Methods.FirstOrDefault(mtd => mtd.Name == "Constants");
   List<Conster> ret = new List<Conster>();

   TypeDefinition lzma = mod.GetType("Lzma" + mod.GetHashCode());
   if (lzma == null)
   {
    lzma = CecilHelper.Inject(mod, injection.MainModule.GetType("Lzma"));
    lzma.IsNotPublic = true;
    lzma.Name = "Lzma" + mod.GetHashCode();
    mod.Types.Add(lzma);
   }

   rand.NextBytes(txt.keyBuff);
   for (int i = 0; i < txt.keyBuff.Length; i++)
    txt.keyBuff[i] &= 0x7f;
   txt.keyBuff[0] = 7; txt.keyBuff[1] = 0;
   txt.resKey = (rand.Next(0x20, 0x80) << 24) | (rand.Next(0x20, 0x80) << 32) |
                (rand.Next(0x20, 0x80) << 16) | (rand.Next(0x20, 0x80) << 0);
   txt.resId = System.Text.Encoding.UTF8.GetString(BitConverter.GetBytes(txt.resKey));
   txt.key = (uint)rand.Next();


   Mutator mutator = new Mutator();

   MethodDefinition cctor = null;

   MethodDefinition init = injection.MainModule.GetType("Encryptions").Methods.FirstOrDefault(mtd => mtd.Name == injectName);
   //init.DeclaringType = mod.GetType("<Module>");
   {

    if (mod.GetType("<Module>").GetStaticConstructor() == null)
    {
     cctor = new MethodDefinition(".cctor", Mono.Cecil.MethodAttributes.Private | Mono.Cecil.MethodAttributes.HideBySig |
       Mono.Cecil.MethodAttributes.SpecialName | Mono.Cecil.MethodAttributes.RTSpecialName |
       Mono.Cecil.MethodAttributes.Static, mod.TypeSystem.Void);
     cctor.Body = new MethodBody(cctor);
     cctor.Body.GetILProcessor().Emit(OpCodes.Ret);
     mod.GetType("<Module>").Methods.Add(cctor);
    }
    else
    {
     cctor = mod.GetType("<Module>").GetStaticConstructor();
    }

    //MethodDefinition cctor = mod.GetType("<Module>").GetStaticConstructor();

    MethodDefinition m = CecilHelper.Inject(mod, init);
    m.DeclaringType = mod.GetType("<Module>");
    Instruction placeholder = null;
    mutator.IntKeys = new int[] { txt.resKey };
    mutator.Mutate(new Random(), m.Body);
    txt.keyInst = mutator.Delayed0;
    placeholder = mutator.Placeholder;


    foreach (Instruction inst in m.Body.Instructions)
    {
     if (inst.Operand is FieldReference)
     {
      if ((inst.Operand as FieldReference).Name == "constTbl")
       inst.Operand = constTbl;
      else if ((inst.Operand as FieldReference).Name == "constBuffer")
       inst.Operand = constBuffer;
     }
     else if (inst.Operand is MethodReference &&
         (inst.Operand as MethodReference).DeclaringType.Name == "LzmaDecoder")
      inst.Operand = lzma.NestedTypes
          .Single(_ => _.Name == "LzmaDecoder").Methods
          .Single(_ => _.Name == (inst.Operand as MethodReference).Name);
    }
    foreach (var i in m.Body.Variables)
     if (i.VariableType.Name == "LzmaDecoder")
      i.VariableType = lzma.NestedTypes.Single(_ => _.Name == "LzmaDecoder");

    if (txt.isDyn)
    {
     Instruction ldloc = placeholder.Previous;
     m.Body.Instructions.Remove(placeholder.Previous);   //ldloc
     CecilHelper.Replace(m.Body, placeholder, new CecilVisitor(txt.invExp, new Instruction[]
                       {
                            ldloc
                       }).GetInstructions());
    }

    ILProcessor psr = cctor.Body.GetILProcessor();
    Instruction begin = cctor.Body.Instructions[0];

    var body = cctor.Body;

    m.Name = ctx_.generator.GenerateNewName();

    Instruction ins = Instruction.Create(OpCodes.Call, m);

    psr.InsertBefore(0, ins);

    mod.GetType("<Module>").Methods.Add(m);


    //for (int i = m.Body.Instructions.Count - 1; i >= 0; i--)
    //{
    // if (m.Body.Instructions[i].OpCode != OpCodes.Ret)
    //  psr.InsertBefore(0, m.Body.Instructions[i]);
    //}
    //cctor.Body.InitLocals = true;
    //foreach (var i in m.Body.Variables)
    // cctor.Body.Variables.Add(i);
   }



   byte[] n = new byte[0x10];

   int typeDefCount = 1;

   for (int i = 0; i < typeDefCount; i++)
   {
    TypeDefinition typeDef = new TypeDefinition(
        "", ctx_.generator.GenerateNewName(),
        Mono.Cecil.TypeAttributes.Class | Mono.Cecil.TypeAttributes.Abstract | Mono.Cecil.TypeAttributes.NotPublic | Mono.Cecil.TypeAttributes.Sealed,
        mod.TypeSystem.Object);
    mod.Types.Add(typeDef);

    int methodCount = 1;


    for (int j = 0; j < methodCount; j++)
    {
     MethodDefinition DecoderMethodRT = CecilHelper.Inject(mod, DecoderMethod);
     DecoderMethodRT.Name = ctx_.generator.GenerateNewName();
     DecoderMethodRT.IsCompilerControlled = true;

     typeDef.Methods.Add(DecoderMethodRT);

     Conster conster = new Conster();
     conster.key0 = (long)rand.Next() * rand.Next();
     conster.key1 = (long)rand.Next() * rand.Next();
     conster.key2 = (long)rand.Next() * rand.Next();
     conster.key3 = rand.Next();
     conster.conster = DecoderMethodRT;


     mutator = new Mutator();
     mutator.LongKeys = new long[]
                       {
                            conster.key0,
                            conster.key1,
                            conster.key2
                       };
     mutator.IntKeys = new int[] { conster.key3 };
     mutator.Mutate(new Random(), DecoderMethodRT.Body);

     foreach (Instruction inst in DecoderMethodRT.Body.Instructions)
      if (inst.Operand is FieldReference)
      {
       if ((inst.Operand as FieldReference).Name == "constTbl")
        inst.Operand = constTbl;
       else if ((inst.Operand as FieldReference).Name == "constBuffer")
        inst.Operand = constBuffer;
      }
     conster.keyInst = mutator.Delayed0;
     ret.Add(conster);
    }

   }

   //foreach (var i in cctor.Body.Instructions)
   //{
   // FieldReference field = i.Operand as FieldReference;
   // if (field != null)
   // {
   //  field.DeclaringType = mod.GetType("<Module>");
   // }
   //}

   //ctx0 = txt;

   return ret.ToArray();
  }

 }
}
