
using LoaderLibrary;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Serialization.Formatters.Binary;

namespace ObfuscationCore.Extractor
{
 public class InstructionVisitor
 {
  //private DynamicILInfo ilInfo;
  public byte[] code;
  public bool ok = true;
  public List<SerializableMethodInstruction> methods = new List<SerializableMethodInstruction>();
  public List<SerializableSigInstruction> signatures = new List<SerializableSigInstruction>();
  public List<SerializableFieldInstruction> fields = new List<SerializableFieldInstruction>();
  public List<SerializableStringInstruction> strings = new List<SerializableStringInstruction>();
  public List<SerializableTypeInstruction> types = new List<SerializableTypeInstruction>();
  public List<SerializableTokenInstruction> tokens = new List<SerializableTokenInstruction>();

  public InstructionVisitor(byte[] code)
  {
   //this.ilInfo = ilinfo;
   this.code = code;
  }

  /*SerializableType SolveType(Type t)
  {
      bool generic = t.IsGenericType;
      List<SerializableType> parameters = new List<SerializableType>();
      foreach (var i in t.GenericTypeArguments)
      {
          parameters.Add(SolveType(i));
      }
      SerializableType r = new SerializableType(t.FullName, t.Module.Assembly.FullName, generic, parameters.ToArray());
      return r;
  }*/
  public void VisitInlineMethodInstruction(InlineMethodInstruction inlineMethodInstruction)
  {
   int i;
   if (methods.Count == 5)
   {
    i = 2;
   }

   if (inlineMethodInstruction.Method.DeclaringType.FullName.Contains("/"))
   {
    ok = false;
   }
   if (inlineMethodInstruction.Method.DeclaringType.FullName.Contains("<"))
   {
    var nimica = "";
   }
   var declaringType = (inlineMethodInstruction.Method.DeclaringType);
   //SerializableMethodInstruction a = new SerializableMethodInstruction(declaringType, inlineMethodInstruction.Method.Name,TypeFromParameters(inlineMethodInstruction.Method.GetParameters()), inlineMethodInstruction.Offset + inlineMethodInstruction.OpCode.Size);
   SerializableMethodInstruction a = new SerializableMethodInstruction(declaringType, inlineMethodInstruction.Method.MethodHandle, inlineMethodInstruction.Offset + inlineMethodInstruction.OpCode.Size);
   methods.Add(a);
  }

  public void VisitInlineSigInstruction(InlineSigInstruction inlineSigInstruction)
  {
   SerializableSigInstruction a = new SerializableSigInstruction(inlineSigInstruction.Signature, inlineSigInstruction.Offset + inlineSigInstruction.OpCode.Size);
   signatures.Add(a);
  }

  public void VisitInlineFieldInstruction(InlineFieldInstruction inlineFieldInstruction)
  {
   //CLR BUG: 
   //OverwriteInt32(ilInfo.GetTokenFor(inlineFieldInstruction.Field.FieldHandle, inlineFieldInstruction.Field.DeclaringType.TypeHandle),
   //    inlineFieldInstruction.Offset + inlineFieldInstruction.OpCode.Size);
   var declaringType = (inlineFieldInstruction.Field.DeclaringType);
   SerializableFieldInstruction a = new SerializableFieldInstruction(declaringType, inlineFieldInstruction.Field.Name, inlineFieldInstruction.Offset + inlineFieldInstruction.OpCode.Size);
   fields.Add(a);

  }

  public void VisitInlineStringInstruction(InlineStringInstruction inlineStringInstruction)
  {
   SerializableStringInstruction a = new SerializableStringInstruction(inlineStringInstruction.String, inlineStringInstruction.Offset + inlineStringInstruction.OpCode.Size);
   strings.Add(a);

  }

  public void VisitInlineTypeInstruction(InlineTypeInstruction inlineTypeInstruction)
  {
   SerializableTypeInstruction a = new SerializableTypeInstruction((inlineTypeInstruction.Type), inlineTypeInstruction.Offset + inlineTypeInstruction.OpCode.Size);

   types.Add(a);
  }

  public void VisitInlineTokInstruction(InlineTokInstruction inlineTokInstruction)
  {
   //!THIS WILL NOT WORK
   //! TODO: SAVE INFO INSTEAD OF TOKENS

   /*MemberInfo mi = inlineTokInstruction.Member;
   int token = 0;
   if (mi.MemberType == MemberTypes.TypeInfo || mi.MemberType == MemberTypes.NestedType)
   {
       Type type = mi as Type;
       token = ilInfo.GetTokenFor(type.TypeHandle);
   }
   else if (mi.MemberType == MemberTypes.Method || mi.MemberType == MemberTypes.Constructor)
   {
       MethodBase m = mi as MethodBase;
       token = ilInfo.GetTokenFor(m.MethodHandle, m.DeclaringType.TypeHandle);
   }
   else if (mi.MemberType == MemberTypes.Field)
   {
       FieldInfo f = mi as FieldInfo;
       //CLR BUG: token = ilInfo.GetTokenFor(f.FieldHandle, f.DeclaringType.TypeHandle);
       token = ilInfo.GetTokenFor(f.FieldHandle);
   }

   SerializableTokenInstruction a = new SerializableTokenInstruction(token, inlineTokInstruction.Offset + inlineTokInstruction.OpCode.Size);
   tokens.Add(a);

   OverwriteInt32(token,
       inlineTokInstruction.Offset + inlineTokInstruction.OpCode.Size);*/
  }

  public RuntimeFieldHandle FindField(Type Owner, string Name)
  {
   return Owner.GetField(Name).FieldHandle;
  }

  public RuntimeMethodHandle FindMethod(Type Owner, string Name, Type[] GivenParameters)
  {
   MemberInfo[] member = Owner.GetMember(Name);
   foreach (var m in member)
   {

    MethodBase methodBase = m as MethodBase;
    ParameterInfo[] parameters = methodBase.GetParameters();
    if (GivenParameters.Length == parameters.Length)
    {
     bool ok = true;
     for (int k = 0; k < parameters.Length; k++)
     {
      if (parameters[k].ParameterType != GivenParameters[parameters[k].Position])
      {
       ok = false;
      }
     }
     if (ok) return methodBase.MethodHandle;
    }

   }
   throw new Exception("Invalid Method Signature!");
  }

  /*public void VisitLists()
  {
      foreach (var a in methods)
      {
          OverwriteInt32(ilInfo.GetTokenFor(FindMethod(a.Owner, a.Name, a.Parameters), a.Owner.TypeHandle), a.Position);
      }

      foreach (var a in signatures)
      {
          OverwriteInt32(ilInfo.GetTokenFor(a.Signature), a.Position);
      }

      foreach (var a in fields)
      {
          //Owner.GetField(Name).FieldHandle
          OverwriteInt32(ilInfo.GetTokenFor(a.Owner.GetField(a.Name).FieldHandle), a.Position);
      }

      foreach (var a in strings)
      {
          OverwriteInt32(ilInfo.GetTokenFor(a.StringValue), a.Position);
      }

      foreach (var a in types)
      {
          OverwriteInt32(ilInfo.GetTokenFor(a.TypeHandle), a.Position);
      }

      foreach (var a in tokens)
      {
          OverwriteInt32(a.Token, a.Position);
      }
  }*/



  Type[] TypeFromParameters(ParameterInfo[] parameters)
  {
   List<Type> p = new List<Type>();
   foreach (ParameterInfo par in parameters)
   {
    if (par.ParameterType.FullName.Contains("/")) ok = false;
    p.Add((par.ParameterType));
   }
   return p.ToArray();
  }
 }
}
