using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Protector.Protections;
using dnlib.DotNet;
using System.IO;
using dnlib.DotNet.Emit;
using System.Diagnostics;
using Protector.Properties;
using Protector.Handler;
using System.Security.Cryptography;
using Protector.Helpers;

namespace Protector.Protections
{
 class PeaceFullWrapper
 {

  private string workingDirectory;
  ProtectorContext protectionContext;
  byte[] injectedLibrary;

  public byte[] Wrap(byte[] input, ProtectorContext context)
  {  
   protectionContext = context;

   PrepareRuntime();
   injectedLibrary = InjectDataToLibrary(input);
   byte[] result = ModifyLoader();

   return result;
  }


  private byte[] ModifyLoader()
  {

   ModuleDef loaderModule = ModuleDefMD.Load(Path.Combine(workingDirectory, "RuntimeInvoker.exe"));

   MethodDef getPayloadMethod = null;

   foreach (TypeDef type in loaderModule.GetTypes())
   {
    foreach (MethodDef method in type.Methods)
    {
     if (method.Name == "GetEngine")
     {
      getPayloadMethod = method;
      break;
     }
    }
   }
   

   CilBody methodBody = getPayloadMethod.Body;

   int ID = 10;

   string idString = IntToSHA(ID);
   loaderModule.Resources.Add(new EmbeddedResource(idString, injectedLibrary,
    ManifestResourceAttributes.Private));

   //foreach (var ins  in methodBody.Instructions)
   //{
   // if(ins.OpCode == OpCodes.Ldc_I4)
   // {
   //  if ((int)ins.Operand == 10)
   //  {
   //   ins.Operand = ID;
   //  }
   // }
   //}

   loaderModule =  new ModuleRenamer().RenameModule(loaderModule, protectionContext);

   //loaderModule = AddAntidump(loaderModule, protectionContext);

   byte[] result = new ModuleHandler().ModuleDefToByte(loaderModule,protectionContext);

   return result;
  }
  public ModuleDef AddAntidump(ModuleDef module, ProtectorContext ctx)
  {

   /* Get runtime type */
   TypeDef rtType = DnLibHelper.GetRuntimeType("Protector.Runtime.AntiDump");

   /* Inject method */
   IEnumerable<IDnlibDef> members = members = InjectHelper.Inject(rtType, module.GlobalType, module);


   /* Methods */
   MethodDef cctor = module.GlobalType.FindOrCreateStaticConstructor();
   MethodDef init = (MethodDef)members.Single(method => method.Name == "Initialize2");
   MethodDef vmprotect = (MethodDef)members.Single(method => method.Name == "__");

   /* Names */
   vmprotect.Name = "InvokeHanler";
   init.Name = "InvokeController";

   /* Instructions */
   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));


   return module;
  }


  private string IntToSHA(int number)
  {
   string id = null;
   byte[] hash = SHA1.Create().ComputeHash(BitConverter.GetBytes(10));

   foreach (var h in hash)
   {
    id += h.ToString("x2").ToUpper();
   }
   return id;
  }



  private void PrepareRuntime()
  {
   string tmp_fld = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
   workingDirectory = tmp_fld;
   if (Directory.CreateDirectory(tmp_fld).Exists)
   {
    string rz_pth = Path.Combine(tmp_fld, Guid.NewGuid().ToString() + ".exe");
    string rz_arch_pth = Path.Combine(tmp_fld, Guid.NewGuid().ToString());
    File.WriteAllBytes(rz_pth, Resources.rz);
    File.WriteAllBytes(rz_arch_pth, Resources.peacefull_wrapper);

    ProcessStartInfo pi = new ProcessStartInfo();
    pi.WorkingDirectory = tmp_fld;
    pi.WindowStyle = ProcessWindowStyle.Hidden;
    pi.CreateNoWindow = true;
    pi.FileName = rz_pth;
    pi.Arguments = " e " + Path.GetFileName(rz_arch_pth) + " *.*";
    Process.Start(pi).WaitForExit();
   }
  }


  private byte[] InjectDataToLibrary(byte[] payload)
  {

   //In
   string libPath = Path.Combine(workingDirectory, "Library.dll");
   string writerPath = Path.Combine(workingDirectory, "Writer.exe");
   string payloadPath = Path.Combine(workingDirectory, "IN.exe");

   //Out
   string outputPath = Path.Combine(workingDirectory, "OUT.dll");

   File.WriteAllBytes(payloadPath,payload);

   ProcessStartInfo si = new ProcessStartInfo();
   si.FileName = writerPath;
   si.Arguments = Path.GetFileName(payloadPath) + " " + Path.GetFileName(outputPath) + " " + Path.GetFileName(libPath);
   si.CreateNoWindow = true;
   si.WorkingDirectory = workingDirectory;
   si.WindowStyle = ProcessWindowStyle.Hidden;

   Process.Start(si).WaitForExit();

   return File.ReadAllBytes(outputPath);
  }


 }
}
