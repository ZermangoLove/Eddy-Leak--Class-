using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using Protector.Protections;
using Protector.Helpers;
using Protector.Protections.Virtualization;

namespace Protector.Protections.RefProxy2
{
 public class RPBasic
 {
  private ProtectorContext ctx;
  private List<MethodDef> usedMethods = new List<MethodDef>();
 }
}
class RPNormal
{
 private ProtectorContext ctx;
 private List<MethodDef> usedMethods = new List<MethodDef>();
 public void Execute(MethodDef method, ProtectorContext context)
 {

  if (method.Name.Contains("Dispose")) return;

  ctx = context;
  ModuleDef module = method.Module;

  RPHelper rPHelper = new RPHelper(ctx);
  DnLibHelper.fixProxy(method.Module);


  if (usedMethods.Contains(method)) return;
  if (!method.HasBody) return;
  foreach (Instruction instruction in method.Body.Instructions.ToArray())
  {
   if (instruction.OpCode == OpCodes.Newobj)
   {
    IMethodDefOrRef methodDefOrRef = instruction.Operand as IMethodDefOrRef;
    if (methodDefOrRef.IsMethodSpec) continue;
    if (methodDefOrRef == null) continue;
    MethodDef methodDef = rPHelper.GenerateMethod(methodDefOrRef, method);

    if (methodDef == null) continue;

    method.DeclaringType.Methods.Add(methodDef);
    usedMethods.Add(methodDef);
    instruction.OpCode = OpCodes.Call;
    instruction.Operand = methodDef;
    //
    usedMethods.Add(methodDef);
   }
   else if (instruction.OpCode == OpCodes.Stfld)
   {
    FieldDef targetField = instruction.Operand as FieldDef;
    if (targetField == null) continue;
    CilBody body = new CilBody();
    body.Instructions.Add(OpCodes.Nop.ToInstruction());
    body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
    body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction());
    body.Instructions.Add(OpCodes.Stfld.ToInstruction(targetField));
    body.Instructions.Add(OpCodes.Ret.ToInstruction());

    var sig = MethodSig.CreateInstance(module.CorLibTypes.Void, targetField.FieldSig.GetFieldType());
    sig.HasThis = true;
    MethodDefUser methodDefUser = new MethodDefUser(ctx.random_generator.GenerateString(), sig)
    {
     Body = body,
     IsHideBySig = true
    };
    usedMethods.Add(methodDefUser);
    method.DeclaringType.Methods.Add(methodDefUser);
    instruction.Operand = methodDefUser;
    instruction.OpCode = OpCodes.Call;
   }
   else if (instruction.OpCode == OpCodes.Ldfld)
   {
    FieldDef targetField = instruction.Operand as FieldDef;
    if (targetField == null) continue;
    MethodDef newmethod = rPHelper.GenerateMethod(targetField, method);
    instruction.OpCode = OpCodes.Call;
    instruction.Operand = newmethod;
    usedMethods.Add(newmethod);
   }
   else if (instruction.OpCode == OpCodes.Call)
   {
    if (instruction.Operand is MemberRef)
    {
     MemberRef methodReference = (MemberRef)instruction.Operand;
     if (!methodReference.FullName.Contains("Collections.Generic") && !methodReference.Name.Contains("ToString") && !methodReference.FullName.Contains("Thread::Start"))
     {
      MethodDef methodDef = rPHelper.GenerateMethod(method.DeclaringType, methodReference, methodReference.HasThis, methodReference.FullName.StartsWith("System.Void"));
      if (methodDef != null)
      {
       usedMethods.Add(methodDef);
       methodDef.Attributes = MethodAttributes.Static;

       //   //My adding to get new type for each proccesed method!
       //   TypeDefUser NewType = new TypeDefUser(ctx.generator.GenerateNewNameChinese(),
       //module.CorLibTypes.Object.TypeDefOrRef);

       //   NewType.Attributes = TypeAttributes.NotPublic |
       //    TypeAttributes.AutoLayout |
       //        TypeAttributes.Class |
       //        TypeAttributes.AnsiClass;

       //   module.Types.Add(NewType);
       //   NewType.Methods.Add(methodDef);
       //   //End of adding

       method.Module.GlobalType.Methods.Add(methodDef);


       instruction.Operand = methodDef;


       methodDef.Body.Instructions.Add(new Instruction(OpCodes.Ret));

      }
     }
    }
   }
  }

  //VM vm = new VM();
  //foreach (var m in usedMethods)
  //{
  // vm.AddTarget(m);
  //}
  //vm.Initialize(module, context);

 }
}
class RPHelper
{

 public ProtectorContext ctx;

 public RPHelper(ProtectorContext context)
 {
  ctx = context;
 }

 public MethodDef GenerateMethod(TypeDef declaringType, object targetMethod, bool hasThis = false, bool isVoid = false)
 {
  MemberRef methodReference = (MemberRef)targetMethod;
  MethodDef methodDefinition = new MethodDefUser(ctx.random_generator.GenerateString(), MethodSig.CreateStatic((methodReference).ReturnType), MethodAttributes.FamANDAssem | MethodAttributes.Family | MethodAttributes.Static);
  methodDefinition.Body = new CilBody();
  if (hasThis)
   methodDefinition.MethodSig.Params.Add(declaringType.Module.Import(declaringType.ToTypeSig()));
  foreach (TypeSig current in methodReference.MethodSig.Params)
   methodDefinition.MethodSig.Params.Add(current);
  methodDefinition.Parameters.UpdateParameterTypes();
  foreach (var current in methodDefinition.Parameters)
   methodDefinition.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg, current));
  methodDefinition.Body.Instructions.Add(Instruction.Create(OpCodes.Call, methodReference));
  methodDefinition.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
  return methodDefinition;
 }
 public MethodDef GenerateMethod(IMethod targetMethod, MethodDef md)
 {
  MethodDef methodDef = new MethodDefUser(ctx.random_generator.GenerateString(), MethodSig.CreateStatic(md.Module.Import(targetMethod.DeclaringType.ToTypeSig())), MethodAttributes.FamANDAssem | MethodAttributes.Family | MethodAttributes.Static);
  methodDef.ImplAttributes = MethodImplAttributes.Managed | MethodImplAttributes.IL;
  methodDef.IsHideBySig = true;
  methodDef.Body = new CilBody();
  for (int x = 0; x < targetMethod.MethodSig.Params.Count; x++)
  {
   methodDef.ParamDefs.Add(new ParamDefUser(ctx.random_generator.GenerateString(), (ushort)(x + 1)));
   methodDef.MethodSig.Params.Add(targetMethod.MethodSig.Params[x]);
  }
  methodDef.Parameters.UpdateParameterTypes();
  for (int x = 0; x < methodDef.Parameters.Count; x++)
  {
   Parameter parameter = methodDef.Parameters[x];
   methodDef.Body.Instructions.Add(new Instruction(OpCodes.Ldarg, parameter));
  }
  methodDef.Body.Instructions.Add(new Instruction(OpCodes.Newobj, targetMethod));
  methodDef.Body.Instructions.Add(new Instruction(OpCodes.Ret));
  return methodDef;
 }
 public MethodDef GenerateMethod(FieldDef targetField, MethodDef md)
 {
  MethodDef methodDefinition = new MethodDefUser(ctx.random_generator.GenerateString(), MethodSig.CreateStatic(md.Module.Import(targetField.FieldType)), MethodAttributes.FamANDAssem | MethodAttributes.Family | MethodAttributes.Static);
  methodDefinition.Body = new CilBody();
  TypeDef declaringType = md.DeclaringType;
  methodDefinition.MethodSig.Params.Add(md.Module.Import(declaringType).ToTypeSig());

  methodDefinition.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
  methodDefinition.Body.Instructions.Add(Instruction.Create(OpCodes.Ldfld, targetField));
  methodDefinition.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
  md.DeclaringType.Methods.Add(methodDefinition);
  return methodDefinition;
 }
}
