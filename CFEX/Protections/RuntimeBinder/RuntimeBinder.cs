using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.Diagnostics;
using Protector.Properties;

namespace Protector.Protections
{
 class RuntimeBinder
 {
  public byte[] RepackModule(byte[] input_module, List<byte[]> libraries)
  {
   byte[] result = null;
   List<string> libs_paths = new List<string>();
   string tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString().ToUpper());
   DirectoryInfo dir = Directory.CreateDirectory(tmpDir);
   if (Directory.Exists(tmpDir))
   {
    foreach (byte[] b in libraries)
    {
     string path = Path.Combine(tmpDir, Guid.NewGuid().ToString().ToUpper())+".dll";
     libs_paths.Add(path);
     try
     {
      File.WriteAllBytes(path, b);
     }
     catch
     {
      //Ex
     }

     try
     {
      /* Proccess by ILRepacker */
      string ilRepackBin = Path.Combine(tmpDir, Guid.NewGuid().ToString().ToUpper() + ".exe");
      string inputModBin = Path.Combine(tmpDir, Guid.NewGuid().ToString().ToUpper() + ".exe");
      File.WriteAllBytes(inputModBin, input_module);
      File.WriteAllBytes(ilRepackBin, Resources.ILRepack);
      if (File.Exists(ilRepackBin) && File.Exists(inputModBin))
      {
       string args = string.Join(" ", libs_paths.Select(p => Path.GetFileName(p)));
       string outFile = Path.Combine(tmpDir, Guid.NewGuid().ToString().ToUpper())+".exe";
       ProcessStartInfo pif = new ProcessStartInfo();
       pif.Arguments = "/out:" + Path.GetFileName(outFile) + " "+ Path.GetFileName(inputModBin) + " "  + args;
       pif.FileName = ilRepackBin;
       pif.CreateNoWindow = true;
       pif.WorkingDirectory = tmpDir;
       pif.WindowStyle = ProcessWindowStyle.Hidden;
       Process.Start(pif).WaitForExit();
       if (File.Exists(outFile))
       {
        result = File.ReadAllBytes(outFile);
        Directory.Delete(tmpDir, true);
       }
      }
     }
     catch
     {
      //Ex
     }
    }
   }
   return result;
  }
 }
}
