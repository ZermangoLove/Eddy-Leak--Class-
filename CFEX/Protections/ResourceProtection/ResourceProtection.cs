using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using dnlib.DotNet;
using Eddy_Protector_Ciphering;
using Eddy_Protector_Core.Core;
using Protector.Helpers;
using dnlib.DotNet.Emit;
using Eddy_Protector.Virtualization.RT.Mutation;

namespace Protector.Protections.ResourcesProtect
{
 class ResourceProtection
 {

  ProtectorContext context;
  ModuleDef CurrentModule;
  public ModuleDef SecureResources(ModuleDef module, ProtectorContext ctx)
  {

   CurrentModule = module;
   context = ctx;

   InjectPhase();
   return module;
  }

  public void InjectPhase()
  {
   var compression = new Compression();
   var moduleCtx = new REContext
   {
    Random = new RandomGenerator(context.random_generator.RandomBytes(32)),
    Context = context,
    Module = CurrentModule,
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

   decomp = compression.GetRuntimeDecompressor(context, CurrentModule, member =>
   {
    if (member is MethodDef)
     annotations.Get<ResourceProtection>(context, member);
   });


   InjectHelpers(context, compression, moduleCtx);

   // Mutate codes
   MutateInitializer(moduleCtx, decomp);

   MethodDef cctor = CurrentModule.GlobalType.FindOrCreateStaticConstructor();
   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, moduleCtx.InitMethod));

   //Protect runtime pethods there ->

   new MDPhase(moduleCtx).Hook();
  }

  void InjectHelpers(ProtectorContext context, Compression compression, REContext moduleCtx)
  {
   var rtName = "Protector.Runtime.Resource";

   TypeDef runtimeType = DnLibHelper.GetRuntimeType(rtName);

   IEnumerable<IDnlibDef> members = InjectHelper.Inject(runtimeType, CurrentModule.GlobalType, CurrentModule);
   foreach (IDnlibDef member in members)
   {
    if (member.Name == "Initialize")
    {
     moduleCtx.InitMethod = (MethodDef)member;
     moduleCtx.InitMethod.Name = context.random_generator.GenerateString();
     //moduleCtx.RuntimeMethods.Add(moduleCtx.InitMethod);
    }
    if (member.Name == "Handler")
    {
     member.Name = context.random_generator.GenerateString();
    }

   }

   var dataType = new TypeDefUser("", context.random_generator.GenerateString(), CurrentModule.CorLibTypes.GetTypeRef("System", "ValueType"));
   dataType.Layout = TypeAttributes.ExplicitLayout;
   dataType.Visibility = TypeAttributes.NestedPrivate;
   dataType.IsSealed = true;
   dataType.ClassLayout = new ClassLayoutUser(1, 0);
   moduleCtx.DataType = dataType;
   CurrentModule.GlobalType.NestedTypes.Add(dataType);

   moduleCtx.DataField = new FieldDefUser(context.random_generator.GenerateString(), new FieldSig(dataType.ToTypeSig()))
   {
    IsStatic = true,
    HasFieldRVA = true,
    InitialValue = new byte[0],
    Access = FieldAttributes.CompilerControlled
   };
   CurrentModule.GlobalType.Fields.Add(moduleCtx.DataField);
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
     typeof(System.Runtime.CompilerServices.RuntimeHelpers).GetMethod("InitializeArray"))));
    return repl.ToArray();
   });
  }
 }
}
