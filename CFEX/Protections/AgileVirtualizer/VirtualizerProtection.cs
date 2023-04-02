using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Diagnostics;
using System.IO;
using Protector.Properties;

namespace Protector.Protections.AgileVirtualizer
{
 class VirtualizerProtection
 {

  private string workingDirectory;
  private string inputProgram;
  private ProtectorContext conetxt;
  private string additionalLibPath;
  public byte[] Virtualize(byte[] inputProgram, ProtectorContext ctx)
  {
   conetxt = ctx;
   Initialize(inputProgram);
   return RunVM();
  }


  private void Initialize(byte[] inputAsmData)
  {
   UnpackRZ();

   string inputAsmPath = Path.Combine(workingDirectory,Guid.NewGuid().ToString().ToString()+".exe");
   inputProgram = inputAsmPath;

   File.WriteAllBytes(inputAsmPath, inputAsmData);

   //foreach (var lib in conetxt.VmNameAndBinary)
   //{
   // File.WriteAllBytes(Path.Combine(workingDirectory,lib.Key), lib.Value);
   //}

   //additionalLibPath = Path.Combine(workingDirectory, conetxt.VmNameAndBinary.ElementAt(0).Key);

  }

  private byte[] RunVM()
  {
   ProcessStartInfo pi = new ProcessStartInfo();
   pi.FileName =  Path.GetFileName(Path.Combine(workingDirectory, "AgileNetInvoker.exe"));
   pi.Arguments = Path.GetFileName(inputProgram) /*+ " " + additionalLibPath*/;
   pi.CreateNoWindow = true;
   pi.WorkingDirectory = workingDirectory;
   pi.WindowStyle = ProcessWindowStyle.Hidden;

   Process.Start(pi).WaitForExit();

   byte[] result = File.ReadAllBytes(Path.Combine(Path.Combine(workingDirectory,"Secured"),Path.GetFileName(inputProgram)));

   string[] libraries = Directory.GetFiles(Path.Combine(Path.Combine(workingDirectory, "Secured")),"*.dll");

   foreach(var f in libraries)
   {
    conetxt.VmNameAndBinary.Add(Path.GetFileName(f), File.ReadAllBytes(f));
   }

   if (result != null)
   {
    Directory.Delete(workingDirectory, true);
   }

   return result;

  }

  private void UnpackRZ()
  {
   string tmp_fld = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
   workingDirectory = tmp_fld;
   if (Directory.CreateDirectory(tmp_fld).Exists)
   {
    string rz_pth = Path.Combine(tmp_fld, Guid.NewGuid().ToString() + ".exe");
    string rz_arch_pth = Path.Combine(tmp_fld, Guid.NewGuid().ToString());
    File.WriteAllBytes(rz_pth, Resources.rz);
    File.WriteAllBytes(rz_arch_pth, Resources.agile_vm);

    ProcessStartInfo pi = new ProcessStartInfo();
    pi.WorkingDirectory = tmp_fld;
    pi.WindowStyle = ProcessWindowStyle.Hidden;
    pi.CreateNoWindow = true;
    pi.FileName = rz_pth;
    pi.Arguments = " e " + Path.GetFileName(rz_arch_pth) + " *.*";
    Process.Start(pi).WaitForExit();
   }
  }



 }
}
