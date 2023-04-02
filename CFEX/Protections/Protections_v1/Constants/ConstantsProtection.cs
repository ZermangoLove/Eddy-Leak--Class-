/* Codded by: Eddy^CZ 2018 
   Date: 15.12.2018
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using Eddy_Protector_Ciphering;
using dnlib.DotNet.MD;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Eddy_Protector_Protections.Protections.Constants
{
 public class ConstantsProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Encode all constants in assembly , based on ConfuserEx constants protection.";
  public override string Id => Author + ".Constants";
  public override string Name => "Constants";

  CEContext cecontext;

  public override void Execute(Context ctx)
  {
   byte[] newSeed = ctx.generator.RandomBytes(32);

   var context = new CEContext();
   context.Context = ctx;
   context.Random = new RandomGenerator(newSeed);
   context.DynCipher = new DynCipherService();
   context.Mode = Mode.Dynamic;
   context.Module = ctx.CurrentModule;
   context.DecoderCount = 1;
   context.ModeHandler = new DynamicMode();
   var compression = new Compression();
   cecontext = context;
   //ctx.RequestNative();

   if ((context.Context.CurrentModule.Cor20HeaderFlags & ComImageFlags.ILOnly) != 0)
    context.Context.CurrentModuleWriterOptions.Cor20HeaderOptions.Flags &= ~ComImageFlags.ILOnly;

   var annotations = new Annotations();

   MethodDef decomp = null;

   if (ctx.RuntimeCompressor != null)
   {
    decomp = ctx.RuntimeCompressor;
   }
   else
   {
    decomp = compression.GetRuntimeDecompressor(ctx, ctx.CurrentModule, member =>
    {
     if (member is MethodDef)
      annotations.Get<ConstantsProtection>(ctx, member);
    });
   }

   InjectHelpers(context);

   // Mutate codes
   MutateInitializer(context, decomp);

   MethodDef cctor = context.Context.CurrentModule.GlobalType.FindOrCreateStaticConstructor();
   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, context.InitMethod));

   var encode_phase = new EncodePhase();

   encode_phase.Execute(context);

   ProtectRuntimeMethods(ctx,context);

  }

  void ProtectRuntimeMethods(Context ctx, CEContext context)
  {
   foreach (var m in context.RuntimeMethods)
   {
    ctx.runtime_protect.runtime_math.DoMathProtection(m, ctx);
    ctx.runtime_protect.runtime_refproxy2.DoRefProxy2(m, ctx);
    ctx.runtime_protect.runtimeControlFlow2.DoControlFlow(m, ctx);
   }
  }

  void InjectHelpers(CEContext moduleCtx)
  {
   IEnumerable<IDnlibDef> members = InjectHelper.Inject(Utils.GetRuntimeType("Eddy_Protector_Runtime.Constant"), moduleCtx.Context.CurrentModule.GlobalType, moduleCtx.Context.CurrentModule);
   foreach (IDnlibDef member in members)
   {
    if (member.Name == "Get")
    {
     moduleCtx.Context.CurrentModule.GlobalType.Remove((MethodDef)member);
     member.Name = moduleCtx.Context.generator.GenerateNewNameChinese();
     moduleCtx.RuntimeMethods.Add((MethodDef)member);
     continue;
    }
    if (member.Name == "b")
    {
     moduleCtx.BufferField = (FieldDef)member;
     member.Name = moduleCtx.Context.generator.GenerateNewNameChinese();
    }

    else if (member.Name == "Initialize")
    {
     moduleCtx.InitMethod = (MethodDef)member;
     member.Name = moduleCtx.Context.generator.GenerateNewNameChinese();
     moduleCtx.RuntimeMethods.Add((MethodDef)member);
    }

   }



   var dataType = new TypeDefUser("", moduleCtx.Context.generator.GenerateNewName(), moduleCtx.Context.CurrentModule.CorLibTypes.GetTypeRef("System", "ValueType"));
   dataType.Layout = TypeAttributes.ExplicitLayout;
   dataType.Visibility = TypeAttributes.NestedPrivate;
   dataType.IsSealed = true;
   moduleCtx.DataType = dataType;
   moduleCtx.Context.CurrentModule.GlobalType.NestedTypes.Add(dataType);

   moduleCtx.DataField = new FieldDefUser(moduleCtx.Context.generator.GenerateNewNameChinese(), new FieldSig(dataType.ToTypeSig()))
   {
    IsStatic = true,
    Access = FieldAttributes.CompilerControlled
   };
   moduleCtx.Context.CurrentModule.GlobalType.Fields.Add(moduleCtx.DataField);

   MethodDef decoder = Utils.GetRuntimeType("Eddy_Protector_Runtime.Constant").FindMethod("Get");

   decoder.Attributes = MethodAttributes.Static;

   decoder.Name = moduleCtx.Context.generator.GenerateNewNameChinese();

   moduleCtx.Decoders = new List<Tuple<MethodDef, DecoderDesc>>();
   for (int i = 0; i < moduleCtx.DecoderCount; i++)
   {
    MethodDef decoderInst = InjectHelper.Inject(decoder, moduleCtx.Context.CurrentModule);
    for (int j = 0; j < decoderInst.Body.Instructions.Count; j++)
    {
     Instruction instr = decoderInst.Body.Instructions[j];
     var method = instr.Operand as IMethod;
     var field = instr.Operand as IField;
     if (instr.OpCode == OpCodes.Call &&
         method.DeclaringType.Name == "Mutation" &&
         method.Name == "Value")
     {
      decoderInst.Body.Instructions[j] = Instruction.Create(OpCodes.Sizeof, new GenericMVar(0).ToTypeDefOrRef());
     }
     else if (instr.OpCode == OpCodes.Ldsfld &&
              method.DeclaringType.Name == "Constant")
     {
      if (field.Name == "b") instr.Operand = moduleCtx.BufferField;
      else throw new NotImplementedException();
     }
    }


    moduleCtx.Context.CurrentModule.GlobalType.Methods.Add(decoderInst);
    moduleCtx.RuntimeMethods.Add(decoderInst);

    var decoderDesc = new DecoderDesc();

    decoderDesc.StringID = (byte)(moduleCtx.Random.NextByte() & 3);

    do decoderDesc.NumberID = (byte)(moduleCtx.Random.NextByte() & 3); while (decoderDesc.NumberID == decoderDesc.StringID);

    do decoderDesc.InitializerID = (byte)(moduleCtx.Random.NextByte() & 3); while (decoderDesc.InitializerID == decoderDesc.StringID || decoderDesc.InitializerID == decoderDesc.NumberID);

    MutationHelper.InjectKeys(decoderInst,
                              new[] { 0, 1, 2 },

                              new int[] {
                               decoderDesc.StringID,
                               decoderDesc.NumberID,
                               decoderDesc.InitializerID,
                              });

    decoderDesc.Data = moduleCtx.ModeHandler.CreateDecoder(decoderInst, moduleCtx);

    moduleCtx.Decoders.Add(Tuple.Create(decoderInst, decoderDesc));

   }
  }

  void MutateInitializer(CEContext moduleCtx, MethodDef decomp)
  {
   moduleCtx.InitMethod.Body.SimplifyMacros(moduleCtx.InitMethod.Parameters);
   List<Instruction> instrs = moduleCtx.InitMethod.Body.Instructions.ToList();
   for (int i = 0; i < instrs.Count; i++)
   {
    Instruction instr = instrs[i];
    var method = instr.Operand as IMethod;

    /* Mutate initializer */
    if (instr.OpCode == OpCodes.Call)
    {
     if (method.DeclaringType.Name == "Mutation" &&
         method.Name == "Crypt")
     {
      Instruction ldBlock = instrs[i - 2];
      Instruction ldKey = instrs[i - 1];
      Debug.Assert(ldBlock.OpCode == OpCodes.Ldloc && ldKey.OpCode == OpCodes.Ldloc);
      instrs.RemoveAt(i);
      instrs.RemoveAt(i - 1);
      instrs.RemoveAt(i - 2);
      instrs.InsertRange(i - 2, moduleCtx.ModeHandler.EmitDecrypt(moduleCtx.InitMethod, moduleCtx, (Local)ldBlock.Operand, (Local)ldKey.Operand)); //This is mutator
     }
     else if (method.DeclaringType.Name == "Lzma" &&
              method.Name == "Decompress")
     {
      instr.Operand = decomp;
     }
    }
   }
   moduleCtx.InitMethod.Body.Instructions.Clear();
   foreach (Instruction instr in instrs)
    moduleCtx.InitMethod.Body.Instructions.Add(instr);


  }
 }
}
