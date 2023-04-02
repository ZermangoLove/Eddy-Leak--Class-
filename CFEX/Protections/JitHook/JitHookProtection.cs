using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using dnlib.DotNet;
using Protector.Helpers;
using System.Security.Cryptography;
using System.IO;
using dnlib.DotNet.Emit;
using System.Reflection;
using Protector.Handler;

namespace Protector.Protections.JitHook
{
 class JitHookProtection
 {

  ModuleDef module;
  Assembly assembly = null;
  byte[] assembly_byte = null;
  MethodDef invoker_method;
  ProtectorContext ctx;
  List<MethodDef> methods_initialized = new List<MethodDef>();

  public byte[] Protect(ModuleDef mod, ProtectorContext context)
  {
   ctx = context;
   module = mod;

   InjectRuntime();
   SearchMethods();
   UpdateModule();
   ProtectMethods();

   return assembly_byte;
  }



  public void InjectRuntime()
  {
   TypeDefUser NewType = new TypeDefUser(ctx.random_generator.GenerateString(),
module.CorLibTypes.Object.TypeDefOrRef);
   NewType.Attributes = dnlib.DotNet.TypeAttributes.NotPublic |
    dnlib.DotNet.TypeAttributes.AutoLayout |
        dnlib.DotNet.TypeAttributes.Class |
        dnlib.DotNet.TypeAttributes.AnsiClass;
   module.Types.Add(NewType);

   var rtType = DnLibHelper.GetRuntimeType("Protector.Runtime.JitHook");
   IEnumerable<IDnlibDef> defs = InjectHelper.Inject(rtType, NewType, module);

   MethodDef invoker = defs.OfType<MethodDef>().Single(method => method.Name == "InvokeInternal");
   invoker_method = invoker;
   invoker.Name = "JitHook";

   int resID = ctx.random_generator.RandomInt();
   string resName = Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(resID)));

   module.Resources.Add(new EmbeddedResource(resName, File.ReadAllBytes("NativeLoader.dll") ,
       ManifestResourceAttributes.Private));

   MutationHelper.InjectKeys(invoker, new int[] { 0}, new int[] { resID });


   MethodDef cctor = module.GlobalType.FindOrCreateStaticConstructor();
   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, invoker));

   UpdateModule();
  }


  

  private void UpdateModule()
  {
   assembly_byte = new ModuleHandler().ModuleDefToByte(module, ctx);
   assembly = Assembly.Load(assembly_byte);
  }

  public void SearchMethods()
  {
   foreach(TypeDef t in module.GetTypes())
   {
    string[] lzmaTypes = new string[] { "Decoder2", "BitDecoder", "BitTreeDecoder", "Decoder", "LzmaDecoder", "LenDecoder", "LiteralDecoder", "OutWindow", "State" };
    if (lzmaTypes.ToList().Contains(t.Name)) continue;
    foreach (MethodDef m in t.Methods)
    {
     if (m == invoker_method) continue;
     if (m.IsConstructor) continue;
     if(m.HasBody)
     {
      MethodBase mb = FindReflectionMethod(m);
      if(mb != null)
      {
        PrepareMethod(m);
        methods_initialized.Add(m);
        //ProtectMethod(m);
      }
     }
    }
   }
  }

  private void PrepareMethod(MethodDef method)
  {
   var processor = method.Body.Instructions;
   for (int i = 0; i < 5; i++)
   {
    processor.Insert(0, OpCodes.Nop.ToInstruction());
   }
  }

  private void ProtectMethods()
  {
   foreach(var method in methods_initialized)
   {
    MethodBase m = FindReflectionMethod(method);
    if (m == null) return;
    System.Reflection.MethodBody body = m.GetMethodBody();
    if(body == null)
    {
     continue;
    }
    byte[] b = body.GetILAsByteArray();
    int size = b.Length;

    int start = SearchArray(assembly_byte, b);
    if (start == -1)
    {
     continue;
    }
    else
    {
     int position = start;
     EncryptDecrypt(b);
     position = start;
     for (int i = 0; i < size; i++)
     {
      assembly_byte[position] = b[i];
      position++;
     }
    }
   } 
   }

  public static void EncryptDecrypt(byte[] data)
  {
   byte[] key = Convert.FromBase64String("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==");

   if (data == null)
    throw new ArgumentNullException("data");

   for (int i = 0; i < data.Length; i++)
    data[i] = (byte)(data[i] ^ key[i % key.Length]);
  }
  private int SearchArray(byte[] src, byte[] pattern)
  {
   int c = src.Length - pattern.Length + 1;
   int j;
   for (int i = 0; i < c; i++)
   {
    if (src[i] != pattern[0]) continue;
    for (j = pattern.Length - 1; j >= 1 && src[i + j] == pattern[j]; j--) ;
    if (j == 0) return i;
   }
   return -1;
  }
  private MethodBase FindReflectionMethod(MethodDef method)
  {

   if (method.IsConstructor)
   {
    foreach (Type t in assembly.DefinedTypes)
    {
     foreach (ConstructorInfo m in t.GetConstructors(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
     {
      var par = m.GetParameters();
      if (par.Length == method.Parameters.Count)
      {
       bool ok = true;
       for (int i = 0; i < par.Length; i++)
       {
        if (par[i].Name != method.Parameters[i].Name) ok = false;
       }
       if (ok) return m;
      }
     }
    }
   }
   else
   {
    foreach (var t in assembly.DefinedTypes)
    {
     foreach (var m in t.DeclaredMethods)
     {
      if (m.Name == method.Name)
      {

       return m;

      }
     }
    }
   }

   return null;
   throw (new Exception("Could not find reflection method: " + method.Name));
  }





 }
}
