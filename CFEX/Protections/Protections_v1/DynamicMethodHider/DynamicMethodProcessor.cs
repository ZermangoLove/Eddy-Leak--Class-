using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mono.Cecil;
using Eddy_Protector_Core.Core;
using System.Reflection;
using Eddy_Protector_Protections.Properties;
using System.IO;
using System.Security.Cryptography;
using Mono.Cecil.Cil;
using ObfuscationCore;
using dnlib.DotNet;

namespace Eddy_Protector_Protections.Protections.DynamicMethodHider
{
 class DynamicMethodProcessor
 {

  DynamicMethodHiderContext DynContext;

  public void Initialize(AssemblyDefinition asm, Context context)
  {
   var ctx = new DynamicMethodHiderContext();
   ctx.assemblyCecil = asm;
   MemoryStream mem = new MemoryStream();
   context.CurrentModule.Write(mem);

   ctx.assemblyReflection = Assembly.Load(mem.ToArray());

   byte[] loaderData = Resources.DynMethRT;
   ctx.loaderAssemblyCecil = AssemblyDefinition.ReadAssembly(new MemoryStream(loaderData));
   ctx.loaderAssemblyReflection = Assembly.Load(loaderData);

   RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(512);
   ctx.privateKey = rsa.ToXmlString(true);
   ctx.publicKey = rsa.ToXmlString(false);

   DynContext = ctx;

   HideLoader();

   ModuleDefinition mod = asm.Modules[0];

   ctx.invoker = mod.Import(typeof(System.Reflection.MethodBase).GetMethod("Invoke", BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic, null, new Type[] { typeof(object), typeof(object[]) }, null));
   ctx.loader = mod.Import(ctx.loaderAssemblyReflection.GetType("LoaderLibrary.ProtectedLoader").GetField("loader"));
   ctx.LoadObjectProtected = mod.Import(ctx.loaderAssemblyReflection.GetType("LoaderLibrary.ProtectedLoader").GetField("LoadObjectProtected"));

   

  }

  public void Execute(MethodDefinition method)
  {
   HideMethod(method);
  }

  public void HideLoader()
  {
   var entryPoint = DynContext.assemblyCecil.EntryPoint;

   TypeDefinition loadertype = null;

   FieldReference loadObjectProtected = null;

   MethodDefinition method1 = null;
   foreach (var mod in DynContext.loaderAssemblyCecil.Modules)
   {
    foreach (var t in mod.Types)
    {
     if (t.Name == "ProtectedLoader") loadertype = t; //ProtectedLoader
    }

    foreach (var f in loadertype.Fields)
    {
     if (f.Name == "LoadObjectProtected")
     {
      loadObjectProtected = f; //LoadObjectProtected
     }
    }

    foreach (var m in loadertype.Methods)
    {
     if (m.Name == "LoadObjectP")
     {
      method1 = m; //LoadObjectP
     }
    }
   }

   DynContext.openLoader = entryPoint.Module.Import(DynContext.loaderAssemblyReflection.GetType("LoaderLibrary.Loader").GetMethod("LoadObject", BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic, null, new Type[] { typeof(string), typeof(bool) }, null));

   DynContext.invoker = entryPoint.Module.Import(typeof(System.Reflection.MethodBase).GetMethod("Invoke", BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic, null, new Type[] { typeof(object), typeof(object[]) }, null));

   loadObjectProtected = entryPoint.Module.Import(loadObjectProtected);

   var processor = entryPoint.Body.GetILProcessor();
   InsertProtectedMethod(method1, loadObjectProtected, processor);

   method1.DeclaringType.Methods.Remove(method1);
  }

  public void InsertProtectedMethod(MethodDefinition method, FieldReference field, ILProcessor processor)
  {
   byte[] b = MethodExtractor.ConvertToBytes(FindReflectionMethod(method, true));
   if (b == null) return;
   string content = Convert.ToBase64String(b);

   //var processor = entryPoint.Body.GetILProcessor();
   var first = processor.Body.Instructions[0];

   var ins_1 = processor.Create(OpCodes.Ldstr, content);
   var ins_2 = processor.Create(OpCodes.Ldc_I4_0);
   var ins_3 = processor.Create(OpCodes.Call, DynContext.openLoader);
   var ins_4 = processor.Create(OpCodes.Stsfld, field);


   processor.InsertAfter(first, ins_1);
   processor.InsertAfter(ins_1, ins_2);
   processor.InsertAfter(ins_2, ins_3);
   processor.InsertAfter(ins_3, ins_4);
  }

  public MethodInfo FindReflectionMethod(MethodDefinition method, bool loader)
  {
   Module moduleReflection = null;

   if (loader)
   {
    moduleReflection = DynContext.loaderAssemblyReflection.GetModules()[0];
   }
   else
   {
    moduleReflection = DynContext.assemblyReflection.GetModules()[0];
   }
   foreach (Type t in moduleReflection.GetTypes())
   {
    foreach (MethodInfo m in t.GetRuntimeMethods())
    {

     int p = method.MetadataToken.ToInt32();
     int r = m.MetadataToken;

     if(p == r)
     {
      return m;
     }

     //if (m.Name == method.Name) return m;
    }
   }
   throw (new Exception("Could not find reflection method: " + method.Name));
  }

  public void HideMethod(MethodDefinition method)
  {

   if (!method.HasBody) return;
   if (method.IsConstructor) return;
   if (method.Name == method.Module.EntryPoint.Name) return;
   if (method.Name == "Dispose") return;
   if (method.Name == "InitializeComponent") return;
   if (method.ReturnType.FullName.Contains("/")) return;
   if (method.DeclaringType.FullName.Contains("/")) return;
   if (!CheckParams(method.Parameters.ToArray())) return;

   var newm = FindReflectionMethod(method, false);

   byte[] b = MethodExtractor.ConvertToBytes(newm);
   if (b == null) return;
   string content = Convert.ToBase64String(b);
   var processor = method.Body.GetILProcessor();
   processor.Body.Instructions.Clear();

   processor.Append(processor.Create(OpCodes.Ldsfld, DynContext.LoadObjectProtected));
   processor.Append(processor.Create(OpCodes.Ldsfld, DynContext.loader));
   processor.Append(processor.Create(OpCodes.Ldc_I4_3));
   processor.Append(processor.Create(OpCodes.Newarr, method.Module.TypeSystem.Object));
   processor.Append(processor.Create(OpCodes.Dup));
   processor.Append(processor.Create(OpCodes.Ldc_I4_0));
   processor.Append(processor.Create(OpCodes.Ldsfld, DynContext.loader));
   processor.Append(processor.Create(OpCodes.Stelem_Ref));
   processor.Append(processor.Create(OpCodes.Dup));
   processor.Append(processor.Create(OpCodes.Ldc_I4_1));
   processor.Append(processor.Create(OpCodes.Ldstr, content));
   processor.Append(processor.Create(OpCodes.Stelem_Ref));
   processor.Append(processor.Create(OpCodes.Dup));
   processor.Append(processor.Create(OpCodes.Ldc_I4_2));

   processor.Append(processor.Create(OpCodes.Ldc_I4, method.Parameters.Count + 1));
   processor.Append(processor.Create(OpCodes.Newarr, method.Module.TypeSystem.Object));

   processor.Append(processor.Create(OpCodes.Dup));
   processor.Append(processor.Create(OpCodes.Ldc_I4, 0));
   if (method.HasThis) processor.Append(processor.Create(OpCodes.Ldarg, 0));
   processor.Append(processor.Create(OpCodes.Stelem_Ref));


   if (method.HasThis)
   {
    for (int i = 1; i <= method.Parameters.Count; i++)
    {
     processor.Append(processor.Create(OpCodes.Dup));
     processor.Append(processor.Create(OpCodes.Ldc_I4, i));
     processor.Append(processor.Create(OpCodes.Ldarg, i));
     processor.Append(processor.Create(OpCodes.Stelem_Ref));
    }
   }
   else
   {
    for (int i = 1; i < method.Parameters.Count; i++)
    {
     processor.Append(processor.Create(OpCodes.Dup));
     processor.Append(processor.Create(OpCodes.Ldc_I4, i));
     processor.Append(processor.Create(OpCodes.Ldarg, i));
     processor.Append(processor.Create(OpCodes.Stelem_Ref));
    }
   }

   processor.Append(processor.Create(OpCodes.Stelem_Ref));
   processor.Append(processor.Create(OpCodes.Callvirt, DynContext.invoker));
   if (method.ReturnType == method.Module.TypeSystem.Void) processor.Append(processor.Create(OpCodes.Pop));
   processor.Append(processor.Create(OpCodes.Ret));
  }

  public bool CheckParams(ParameterDefinition[] parameters)
  {
   foreach (var p in parameters)
   {
    if (p.ParameterType.FullName.Contains("/")) return false;
   }
   return true;
  }




 }
}
