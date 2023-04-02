using LoaderLibrary;
using ObfuscationCore.Extractor;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Serialization.Formatters.Binary;


namespace ObfuscationCore
{
 public class MethodExtractor
 {
  static InstructionVisitor visitor;

  #region NotUsed

  /*static SerializableType SolveType(Type t)
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

  #endregion

  public static byte[] ConvertToBytes(MethodInfo Method)
  {
   MethodBody body = Method.GetMethodBody();

   byte[] code = body.GetILAsByteArray();
   //File.WriteAllBytes("dump_type.bin", code);
   InstructionsParser reader = new InstructionsParser(Method);
   visitor = new InstructionVisitor(code);
   reader.Accept(visitor);

   File.WriteAllBytes("dump_old.bin", visitor.code);

   SerializableMethod m = new SerializableMethod(Method.Name + "_dyn", (Method.ReturnType), GetParameterTypesString(Method), (Method.DeclaringType), visitor.code, GetSigTypeString(body), GetSigPinned(body), body.MaxStackSize, visitor.methods, visitor.signatures, visitor.fields, visitor.strings, visitor.types, visitor.tokens);

   MemoryStream streamMemory = new MemoryStream();
   BinaryFormatter formatter = new BinaryFormatter();
   formatter.Serialize(streamMemory, m); return streamMemory.GetBuffer();
  }

  private static Type[] GetSigTypeString(MethodBody body)
  {
   List<Type> r = new List<Type>();
   foreach (LocalVariableInfo lvi in body.LocalVariables)
   {
    r.Add((lvi.LocalType));
   }
   return r.ToArray();
  }

  private static bool[] GetSigPinned(MethodBody body)
  {
   List<bool> r = new List<bool>();
   foreach (LocalVariableInfo lvi in body.LocalVariables)
   {
    r.Add(lvi.IsPinned);
   }
   return r.ToArray();
  }

  private static byte[] GetSignature(MethodBody body)
  {

   SignatureHelper sig = SignatureHelper.GetLocalVarSigHelper();
   foreach (LocalVariableInfo lvi in body.LocalVariables)
   {
    sig.AddArgument(lvi.LocalType, lvi.IsPinned);
   }
   return sig.GetSignature();
  }



  private static void SetExceptions(MethodBody body, DynamicILInfo ilInfo)
  {
   IList<ExceptionHandlingClause> ehcs = body.ExceptionHandlingClauses;
   int ehCount = ehcs.Count;
   if (ehCount == 0) return;

   // Let us do FAT exception header
   int size = 4 + 24 * ehCount;
   byte[] exceptions = new byte[size];

   exceptions[0] = 0x01 | 0x40; //Offset: 0, Kind: CorILMethod_Sect_EHTable | CorILMethod_Sect_FatFormat
   OverwriteInt32(size, 1, exceptions);  // Offset: 1, DataSize: n * 24 + 4

   int pos = 4;
   foreach (ExceptionHandlingClause ehc in ehcs)
   {
    // 
    // Flags, TryOffset, TryLength, HandlerOffset, HandlerLength, 
    //
    OverwriteInt32((int)ehc.Flags, pos, exceptions); pos += 4;
    OverwriteInt32(ehc.TryOffset, pos, exceptions); pos += 4;
    OverwriteInt32(ehc.TryLength, pos, exceptions); pos += 4;
    OverwriteInt32(ehc.HandlerOffset, pos, exceptions); pos += 4;
    OverwriteInt32(ehc.HandlerLength, pos, exceptions); pos += 4;

    //
    // ClassToken or FilterOffset
    //
    switch (ehc.Flags)
    {
     case ExceptionHandlingClauseOptions.Clause:
      int token = ilInfo.GetTokenFor(ehc.CatchType.TypeHandle);
      OverwriteInt32(token, pos, exceptions);
      break;
     case ExceptionHandlingClauseOptions.Filter:
      OverwriteInt32(ehc.FilterOffset, pos, exceptions);
      break;
     case ExceptionHandlingClauseOptions.Fault:
      throw new NotSupportedException("dynamic method does not support fault clause");
     case ExceptionHandlingClauseOptions.Finally:
      break;
    }
    pos += 4;
   }

   ilInfo.SetExceptions(exceptions);
  }

  public static void OverwriteInt32(int value, int pos, byte[] array)
  {
   array[pos++] = (byte)value;
   array[pos++] = (byte)(value >> 8);
   array[pos++] = (byte)(value >> 16);
   array[pos++] = (byte)(value >> 24);
  }

  static Type[] GetParameterTypes(MethodInfo method)
  {
   return new[] { method.DeclaringType }.Concat(method.GetParameters().Select(pi => pi.ParameterType)).ToArray();
  }

  static Type[] GetParameterTypesString(MethodInfo method)
  {
   return new[] { (method.DeclaringType) }.Concat(method.GetParameters().Select(pi => (pi.ParameterType))).ToArray();
  }
 }
}
