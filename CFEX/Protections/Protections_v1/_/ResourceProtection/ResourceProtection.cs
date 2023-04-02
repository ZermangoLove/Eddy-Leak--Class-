using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using Confuser.DynCipher;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Runtime.CompilerServices;

namespace Eddy_Protector.Protections.ResourceProtection
{
 class ResourceProtection : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Resource protection , based on cfex!";
  public override string Id => Author + ".Resource protection";
  public override string Name => "Resource protection";


  public override void Execute(Context ctx)
  {
   InjectPhase(ctx);
  }

  public void InjectPhase(Context ctx)
  {
   var compression = new Compression();
   var moduleCtx = new REContext
   {
    Random = new RandomGenerator(ctx.generator.RandomBytes(32)),
    Context = ctx,
    Module = ctx.CurrentModule,
    DynCipher = new DynCipherService()
   };

   // Extract parameters
   moduleCtx.Mode = Mode.Dynamic;

   switch (moduleCtx.Mode)
   {
    case Mode.Dynamic:
     moduleCtx.ModeHandler = new DynamicMode();
     break;
    default:
     throw new NotImplementedException();
   }

   var annotations = new Annotations();

   MethodDef decomp = null;

   if (ctx.RuntimeCompressor != null)
   {
    decomp = ctx.RuntimeCompressor;
   }
   else
   {
    decomp = compression.GetRuntimeDecompressor(ctx,ctx.CurrentModule, member =>
    {
     if (member is MethodDef)
      annotations.Get<ResourceProtection>(ctx, member);
    });
   }

   // Inject helpers

   //decomp.Name = ctx.generator.GenerateNewName();

   //ctx.runtime_protect.runtime_controlflow1.DoControlFlow(decomp, ctx);

   InjectHelpers(ctx, compression, moduleCtx);

   // Mutate codes
   MutateInitializer(moduleCtx, decomp);

   MethodDef cctor = ctx.CurrentModule.GlobalType.FindOrCreateStaticConstructor();
   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, moduleCtx.InitMethod));

   ProtectRuntimeMethods(ctx, moduleCtx);

   new MDPhase(moduleCtx).Hook();
  }

  void ProtectRuntimeMethods(Context ctx, REContext ctx_re)
  {
   foreach (var m in ctx_re.RuntimeMethods)
   {
    //ctx.runtime_protect.runtime_mutation.DoMutation(m, ctx);

    ctx.runtime_protect.runtime_math.DoMathProtection(m, ctx);
    ctx.runtime_protect.runtime_refproxy2.DoRefProxy2(m, ctx);
    ctx.runtime_protect.runtime_controlflow2.DoControlFlow(m, ctx);

   }
  }

  void InjectHelpers(Context context, Compression compression, REContext moduleCtx)
  {
   var rtName = /*true ? "Confuser.Runtime.Resource_Packer" : */"Confuser.Runtime.Resource";
   IEnumerable<IDnlibDef> members = InjectHelper.Inject(Utils.GetRuntimeType(rtName), context.CurrentModule.GlobalType, context.CurrentModule);
   foreach (IDnlibDef member in members)
   {
    if (member.Name == "Initialize")
    {
     moduleCtx.InitMethod = (MethodDef)member;
     moduleCtx.InitMethod.Name = context.generator.GenerateNewName();
     moduleCtx.RuntimeMethods.Add(moduleCtx.InitMethod);
    }
    if (member.Name == "Handler")
    {
     member.Name = context.generator.GenerateNewName();
    }
   }

   var dataType = new TypeDefUser("", context.generator.GenerateNewName(), context.CurrentModule.CorLibTypes.GetTypeRef("System", "ValueType"));
   dataType.Layout = TypeAttributes.ExplicitLayout;
   dataType.Visibility = TypeAttributes.NestedPrivate;
   dataType.IsSealed = true;
   dataType.ClassLayout = new ClassLayoutUser(1, 0);
   moduleCtx.DataType = dataType;
   context.CurrentModule.GlobalType.NestedTypes.Add(dataType);

   moduleCtx.DataField = new FieldDefUser(context.generator.GenerateNewName(), new FieldSig(dataType.ToTypeSig()))
   {
    IsStatic = true,
    HasFieldRVA = true,
    InitialValue = new byte[0],
    Access = FieldAttributes.CompilerControlled
   };
   context.CurrentModule.GlobalType.Fields.Add(moduleCtx.DataField);
  }

  void MutateInitializer(REContext moduleCtx, MethodDef decomp)
  {
   moduleCtx.InitMethod.Body.SimplifyMacros(moduleCtx.InitMethod.Parameters);
   List<Instruction> instrs = moduleCtx.InitMethod.Body.Instructions.ToList();
   for (int i = 0; i < instrs.Count; i++)
   {
    Instruction instr = instrs[i];
    var method = instr.Operand as IMethod;
    if (instr.OpCode == OpCodes.Call)
    {
     if (method.DeclaringType.Name == "Mutation" &&
         method.Name == "Crypt")
     {
      Instruction ldBlock = instrs[i - 2];
      Instruction ldKey = instrs[i - 1];
      instrs.RemoveAt(i);
      instrs.RemoveAt(i - 1);
      instrs.RemoveAt(i - 2);
      instrs.InsertRange(i - 2, moduleCtx.ModeHandler.EmitDecrypt(moduleCtx.InitMethod, moduleCtx, (Local)ldBlock.Operand, (Local)ldKey.Operand));
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

   MutationHelper.ReplacePlaceholder(moduleCtx.InitMethod, arg =>
   {
    var repl = new List<Instruction>();
    repl.AddRange(arg);
    repl.Add(Instruction.Create(OpCodes.Dup));
    repl.Add(Instruction.Create(OpCodes.Ldtoken, moduleCtx.DataField));
    repl.Add(Instruction.Create(OpCodes.Call, moduleCtx.Module.Import(
     typeof(RuntimeHelpers).GetMethod("InitializeArray"))));
    return repl.ToArray();
   });
  }

 }
}
