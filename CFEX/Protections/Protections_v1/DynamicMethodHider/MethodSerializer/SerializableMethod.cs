using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace LoaderLibrary
{
 [Serializable]
 public class SerializableMethod
 {
  public string Name;
  public Type ReturnType;
  public Type[] ParamTypes;
  public Type OwnerType;
  public byte[] Code;
  public Type[] Arguments;
  public bool[] ArgPinned;
  public int MaxStack;
  public SerializableMethodInstruction[] Methods;
  public SerializableSigInstruction[] Signatures;
  public SerializableFieldInstruction[] Fields;
  public SerializableStringInstruction[] Strings;
  public SerializableTypeInstruction[] Types;
  public SerializableTokenInstruction[] Tokens;

  public SerializableMethod(string name,
   Type return_type,
   Type[] param_types,
   Type owner_type,
   byte[] code,
   Type[] arguments,
   bool[] argpinned,
   int max_stack,
   List<SerializableMethodInstruction> methods,
   List<SerializableSigInstruction> signatures,
   List<SerializableFieldInstruction> fields,
   List<SerializableStringInstruction> strings,
   List<SerializableTypeInstruction> types,
   List<SerializableTokenInstruction> tokens)
  {
   Name = name;
   ReturnType = return_type;
   ParamTypes = param_types;
   OwnerType = owner_type;
   Code = code;
   Arguments = arguments;
   ArgPinned = argpinned;
   MaxStack = max_stack;
   Methods = methods.ToArray();
   Signatures = signatures.ToArray();
   Fields = fields.ToArray();
   Strings = strings.ToArray();
   Types = types.ToArray();
   Tokens = tokens.ToArray();
  }

  public SerializableMethod(SerializationInfo info, StreamingContext ctxt)
  {
   Name = (string)info.GetValue("name", typeof(string));
   ReturnType = (Type)info.GetValue("return_type", typeof(Type));
   ParamTypes = (Type[])info.GetValue("param_types", typeof(Type[]));
   OwnerType = (Type)info.GetValue("owner_type", typeof(Type));
   Code = (byte[])info.GetValue("code", typeof(byte[]));
   Arguments = (Type[])info.GetValue("arguments", typeof(Type[]));
   ArgPinned = (bool[])info.GetValue("argpinned", typeof(bool[]));
   MaxStack = (int)info.GetValue("max_stack", typeof(int));
   Methods = (SerializableMethodInstruction[])info.GetValue("methods", typeof(SerializableMethodInstruction[]));
   Signatures = (SerializableSigInstruction[])info.GetValue("signatures", typeof(SerializableSigInstruction[]));
   Fields = (SerializableFieldInstruction[])info.GetValue("fields", typeof(SerializableFieldInstruction[]));
   Strings = (SerializableStringInstruction[])info.GetValue("strings", typeof(SerializableStringInstruction[]));
   Types = (SerializableTypeInstruction[])info.GetValue("types", typeof(SerializableTypeInstruction[]));
   Tokens = (SerializableTokenInstruction[])info.GetValue("tokens", typeof(SerializableTokenInstruction[]));
  }

  public void GetObjectData(SerializationInfo info, StreamingContext context)
  {
   info.AddValue("name", Name);
   info.AddValue("return_type", ReturnType);
   info.AddValue("param_types", ParamTypes);
   info.AddValue("owner_type", OwnerType);

   info.AddValue("code", Code);
   info.AddValue("arguments", Arguments);
   info.AddValue("argpinned", ArgPinned);
   info.AddValue("max_stack", MaxStack);

   info.AddValue("methods", Methods);
   info.AddValue("signatures", Signatures);
   info.AddValue("fields", Fields);
   info.AddValue("strings", Strings);
   info.AddValue("types", Types);
   info.AddValue("tokens", Tokens);
  }
 }



 /*[Serializable]
 public class SerializableType
 {
     public string Name;
     public string Assembly;
     public bool Generic;
     public SerializableType[] GenericArguments;

     public SerializableType(string _name, string _assembly, bool _generic, SerializableType[] _genericArguments)
     {
         Name = _name;
         Assembly = _assembly;
         Generic = _generic;
         GenericArguments = _genericArguments;
     }

     public SerializableType(SerializationInfo info, StreamingContext ctxt)
     {
         Name = (string)info.GetValue("name", typeof(string));
         Assembly = (string)info.GetValue("assembly", typeof(string));
         Generic = (bool)info.GetValue("generic", typeof(bool));
         GenericArguments = (SerializableType[])info.GetValue("generic_arguments", typeof(SerializableType[]));
     }

     public void GetObjectData(SerializationInfo info, StreamingContext context)
     {
         info.AddValue("name", Name);
         info.AddValue("assembly", Assembly);
         info.AddValue("generic", Generic);
         info.AddValue("generic_arguments", GenericArguments);
     }
 }*/
}
