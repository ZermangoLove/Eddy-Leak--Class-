using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;
using Protector.Utils;
using Protector.IlDyn;

namespace Protector
{

 class EFileWriter
 {
  private List<byte[]> Data;
  public EFileWriter() {Data = new List<byte[]>(); }

  public void AddData(byte[] data)
  {
   Data.Add(data);
  }
  public byte[] Create()
  {
   return Compose(Data);
  }
  private byte[] Compose(List<byte[]> data)
  {

   /*#BLOB Header -----------------------------------------------------*/

   /* ----------- EXAMPLE OF HEADER LOOK -------------------
    * HDR = Total files stored in blob ex: 3
    * Lenght of file1 ex: 256b (1)
    * lenght of file2 ex: 156b (2)
    * lenght of file3 ex: 32b  (3)
    * ...
    * ....
    * ...
    * ......
    * etc....
    * --- [END OF HEADER] ---
    */

   //Part 1: Numbers
   int blobCapacity = data.Count;
   int[] blobPartslLenghts = data.Select(n => n.Length).ToArray();
   //Part 2: file lenghts
   byte[] blobCapacityByte = BitConverter.GetBytes(blobCapacity);
   List<byte[]> blobPartslLenghtsBytes = new List<byte[]>();
   //
   //Part 3: Store part lenghts
   foreach (var partLen in blobPartslLenghts)
   {
    blobPartslLenghtsBytes.Add(BitConverter.GetBytes(partLen));
   }
   //
   List<byte[]> blobHeaderList = new List<byte[]>();
   blobHeaderList.Add(blobCapacityByte);
   foreach (var part in blobPartslLenghtsBytes)
   {
    blobHeaderList.Add(part);
   }
   int BLOB_LENGHT = sizeof(int) + (data.Count * sizeof(int));
   byte[] BLOB_HEADER = new byte[BLOB_LENGHT];

   int counter1 = 0;
   foreach (var entry in blobHeaderList)
   {
    foreach (var b in entry)
    {
     BLOB_HEADER[counter1] = b;
     counter1++;
    }
   }
   /*#BLOB Header -----------------------------------------------------*/

   List<byte[]> BLOBList = new List<byte[]>();
   BLOBList.Add(BLOB_HEADER); //Add header

   //Part 4: Store data
   int totalLenght = 0;
   foreach (byte[] pack in data)
   {
    byte[] encrypted_chunk = EncryptChunk(pack, pack.Length);
    BLOBList.Add(encrypted_chunk);
    totalLenght += pack.Length;
   }

   int blobLength = BLOB_HEADER.Length + totalLenght;
   byte[] BLOB_PLAIN = new byte[blobLength];

   int counter2 = 0;
   foreach (byte[] dpart in BLOBList)
   {
    foreach (var b in dpart)
    {
     BLOB_PLAIN[counter2] = b;
     counter2++;
    }
   }
   return BLOB_PLAIN;
  }

  private byte[] EncryptChunk(byte[] data, int key)
  {
   List<ulong> e_0 = new List<ulong>(); //P1
   ulong[] i = SHA1.Create().ComputeHash(BitConverter.GetBytes(key)).Select(b => (ulong)(b << 8 | b << 16 | b << 24)).ToArray();
   foreach (byte b in data)
   {
    ulong n = (ulong)(b << 8 | b << 16 | b << 24); //byte to ulong
    ulong o = 0; //Initializer
    foreach (ulong iv in i)
    {
     o ^= iv; //Xor all IVS to o
    }
    o = n ^ o; //Xor o to
    e_0.Add(o);
   }
   return e_0.Select(b => (byte)(b | (b >> 8) | (b >> 16) | (b >> 24))).ToArray();
  }
 }

 class StringHiderProtection
 {
  private ModuleDef Module;
  private List<int> Initialzers = new List<int>();
  private EFileWriter EFile;
  private MethodDef Init;
  private MethodDef Get;
  private int UsedIntitalizers = -1;
  public StringHiderProtection(ModuleDef module)
  {
   Module = module;
   EFile = new EFileWriter();
   Initialize();
  }

  private void Initialize()
  {

   TypeDefUser NewType = new TypeDefUser("Const","Const",
Module.CorLibTypes.Object.TypeDefOrRef);
   NewType.Attributes = dnlib.DotNet.TypeAttributes.NotPublic |
    dnlib.DotNet.TypeAttributes.AutoLayout |
        dnlib.DotNet.TypeAttributes.Class |
        dnlib.DotNet.TypeAttributes.AnsiClass;
   Module.Types.Add(NewType);
   
   var rtType = DnLibHelper.GetRuntimeType("Runtime.StringHider");
   IEnumerable<IDnlibDef> defs = InjectHelper.Inject(rtType, NewType, Module);
   Init = defs.OfType<MethodDef>().Single(method => method.Name == "Intitialize");
   Get = defs.OfType<MethodDef>().Single(method => method.Name == "Get");
   MethodDef test = defs.OfType<MethodDef>().Single(method => method.Name == "CopyRight");
   new LocalsToFields().ProtectMethod(Init);
   new LocalsToFields().ProtectMethod(Get);

   new IlDyn.IL2Dynamic().ConvertToDynamic(test, Module);
   MethodDef cctor = Module.GlobalType.FindOrCreateStaticConstructor();
   cctor.Body.Instructions.Insert(0, new Instruction(OpCodes.Call, test));
   ProtectMethod(test);
   new LocalsToFields().ProtectMethod(test);
  }

  public void ProtectMethod(MethodDef method)
  {
   int insCnt = method.Body.Instructions.Count;
   for (int i = 0; i < insCnt; i++)
   {
    Instruction ins = method.Body.Instructions[i];
    if (ins.OpCode == OpCodes.Ldstr)
    {
     MethodDef DecMethod = Get;
     HideString(i, method, ins, DecMethod);
    }
   }
  }


  public void ProtectAllMethods()
  {
   foreach (var t in Module.GetTypes())
   {
    foreach (var m in t.Methods)
    {
     if (m.HasBody)
     {
      ProtectMethod(m);
     }
    }
   }
  }

  public void HideString(int CurrentPos, MethodDef method, Instruction ins, MethodDef TargetMethod)
  {
   string operand = ins.Operand.ToString();
   byte[] data = Encoding.ASCII.GetBytes(operand);
   EFile.AddData(data);
   UsedIntitalizers++;
   Initialzers.Add(UsedIntitalizers);

   method.Body.Instructions.RemoveAt(CurrentPos);
   method.Body.Instructions.Insert(CurrentPos, OpCodes.Ldc_I4.ToInstruction(UsedIntitalizers));
   method.Body.Instructions.Insert(CurrentPos + 1, new Instruction(OpCodes.Call, TargetMethod));
  }

  public void Finish()
  {
   int id = new Random().Next(int.MaxValue);
   string idStr = GetName(id);
   byte[] data = EFile.Create();
   string b64 = Convert.ToBase64String(data);
   Module.Resources.Add(new EmbeddedResource(idStr, data,
ManifestResourceAttributes.Private));
   MutationHelper.InjectKeys(Init,new int[] { 0 }, new int[] { id });
   MethodDef cctor = Module.GlobalType.FindOrCreateStaticConstructor();
   cctor.Body.Instructions.Insert(0, new Instruction(OpCodes.Call, Init));
  }

  private string GetName(int id)
  {
   byte[] hash = SHA1.Create().ComputeHash(BitConverter.GetBytes(id));
   string result = null;
   foreach (var h in hash)
   {
    result += h.ToString("x2").ToUpper();
   }
   return result;
  }


 }
}
