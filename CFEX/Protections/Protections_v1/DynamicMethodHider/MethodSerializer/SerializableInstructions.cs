using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace LoaderLibrary
{
 [Serializable]
 public class SerializableMethodInstruction
 {

  public int Position;
  public Type Owner;
  public RuntimeMethodHandle Handle;

  public SerializableMethodInstruction(Type owner, RuntimeMethodHandle handle, int pos)
  {
   Owner = owner;
   Handle = handle;
   Position = pos;

  }


  public SerializableMethodInstruction(SerializationInfo info, StreamingContext ctxt)
  {
   //Get the values from info and assign them to the appropriate properties
   Owner = (Type)info.GetValue("owner", typeof(Type));
   Handle = (RuntimeMethodHandle)info.GetValue("handle", typeof(RuntimeMethodHandle));
   Position = (int)info.GetValue("position", typeof(int));
  }

  public void GetObjectData(SerializationInfo info, StreamingContext context)
  {

   info.AddValue("owner", Owner);
   info.AddValue("handle", Handle);
   info.AddValue("position", Position);
  }
 }

 [Serializable]
 public class SerializableSigInstruction
 {
  public byte[] Signature;
  public int Position;

  public SerializableSigInstruction(byte[] signature, int pos)
  {
   Signature = signature;
   Position = pos;
  }


  public SerializableSigInstruction(SerializationInfo info, StreamingContext ctxt)
  {
   //Get the values from info and assign them to the appropriate properties
   Signature = (byte[])info.GetValue("signature", typeof(byte[]));
   Position = (int)info.GetValue("position", typeof(int));
  }

  public void GetObjectData(SerializationInfo info, StreamingContext context)
  {
   info.AddValue("signature", Signature);
   info.AddValue("position", Position);
  }
 }

 [Serializable]
 public class SerializableFieldInstruction
 {
  public Type Owner;
  public string Name;
  //public RuntimeFieldHandle FieldHandle;
  public int Position;

  public SerializableFieldInstruction(Type owner, string name, int pos)
  {
   Owner = owner;
   Name = name;
   Position = pos;
  }


  public SerializableFieldInstruction(SerializationInfo info, StreamingContext ctxt)
  {
   //Get the values from info and assign them to the appropriate properties
   Owner = (Type)info.GetValue("owner", typeof(Type));
   Name = (string)info.GetValue("name", typeof(string));
   Position = (int)info.GetValue("position", typeof(int));
  }

  public void GetObjectData(SerializationInfo info, StreamingContext context)
  {
   info.AddValue("owner", Owner);
   info.AddValue("name", Name);
   info.AddValue("position", Position);
  }
 }


 [Serializable]
 public class SerializableStringInstruction
 {
  public string StringValue;
  public int Position;

  public SerializableStringInstruction(string string_value, int pos)
  {
   StringValue = string_value;
   Position = pos;
  }


  public SerializableStringInstruction(SerializationInfo info, StreamingContext ctxt)
  {
   //Get the values from info and assign them to the appropriate properties
   StringValue = (string)info.GetValue("string_value", typeof(string));
   Position = (int)info.GetValue("position", typeof(int));
  }

  public void GetObjectData(SerializationInfo info, StreamingContext context)
  {
   info.AddValue("string_value", StringValue);
   info.AddValue("position", Position);
  }
 }


 [Serializable]
 public class SerializableTypeInstruction
 {
  public Type Value;
  public int Position;

  public SerializableTypeInstruction(Type value, int pos)
  {
   Value = value;
   Position = pos;
  }


  public SerializableTypeInstruction(SerializationInfo info, StreamingContext ctxt)
  {
   //Get the values from info and assign them to the appropriate properties
   Value = (Type)info.GetValue("value", typeof(Type));
   Position = (int)info.GetValue("position", typeof(int));
  }

  public void GetObjectData(SerializationInfo info, StreamingContext context)
  {
   info.AddValue("value", Value);
   info.AddValue("position", Position);
  }
 }

 [Serializable]
 public class SerializableTokenInstruction
 {
  public int Token;
  public int Position;

  public SerializableTokenInstruction(int token, int pos)
  {
   Token = token;
   Position = pos;
  }


  public SerializableTokenInstruction(SerializationInfo info, StreamingContext ctxt)
  {
   //Get the values from info and assign them to the appropriate properties
   Token = (int)info.GetValue("token", typeof(int));
   Position = (int)info.GetValue("position", typeof(int));
  }

  public void GetObjectData(SerializationInfo info, StreamingContext context)
  {
   info.AddValue("token", Token);
   info.AddValue("position", Position);
  }
 }
}
