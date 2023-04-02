using Protector.Properties;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;


namespace Protector.Protections.Prepacker
{
 //class Prepacker
 //{
 // public void Prepack(ProtectorContext protector_context)
 // {
 //  ModuleHandler m = new ModuleHandler();
   
 //  byte[] asm_input = m.ModuleDefToByte(protector_context.input_module_def);

 //  //byte[] virtualized = new VM().Protect(asm_input, protector_context);

 //  byte[] asm_protected = new PrepackerPhase().ProtectModern(asm_input, protector_context);
 //  protector_context.output_module_byte = asm_protected;
 // }
 //}

 class PrepackerPhase
 {
  public byte[] ProtectModern(byte[] input_asembly)
  {
   byte[] result = null;
   var paths = PrepareRuntime();
   //paths = [0] = dir , [1] = ilp , [2] = tm
   var tar_p = Path.Combine(paths[0], Guid.NewGuid().ToString().ToUpper() + ".exe");
   var tar_p_abs = Path.GetFileName(tar_p);
   bool targetOk = false;

   try
   {
    File.WriteAllBytes(tar_p, input_asembly);
   }
   catch
   {

   }
   finally
   {
    targetOk = true;
   }

   bool ilp_ok = false;

   if (targetOk)
   {
    var psi_ilp = new ProcessStartInfo();
    psi_ilp.FileName = Path.GetFileName(paths[1]);
    psi_ilp.Arguments = " -out=\"OUT\" -nogui -nologo -force-load  -embed-dlls -quiet -name32=Eddy^CZ_.dl -name64=Eddy^CZ__.dll " + tar_p_abs;
    psi_ilp.WorkingDirectory = paths[0];
    psi_ilp.CreateNoWindow = true;
    psi_ilp.WindowStyle = ProcessWindowStyle.Hidden;
    Process.Start(psi_ilp).WaitForExit();
    ilp_ok = true;
   }

   bool th_ok = false;
   var tar_p_th_out = Path.GetExtension(tar_p_abs).Replace(".exe", "^_.exe");

   if (ilp_ok)
   {
    var psi_th = new ProcessStartInfo();
    psi_th.FileName = Path.GetFileName(paths[2]);
    psi_th.Arguments = @" /protect $tmp.tmd /inputfile OUT/" + tar_p_abs + " /outputfile OUT/" + tar_p_th_out;
    psi_th.WorkingDirectory = paths[0];
    //psi_th.WindowStyle = ProcessWindowStyle.Hidden;
    //psi_th.CreateNoWindow = true;
    Process.Start(psi_th).WaitForExit();
    th_ok = true;
   }

   if (th_ok)
   {
    result = File.ReadAllBytes(Path.Combine(paths[0], "OUT/" + tar_p_th_out));
    if (result.Length != 0)
    {
     Directory.Delete(paths[0], true);
    }
   }
   return result;
  }

  private string[] PrepareRuntime()
  {
   string[] result = new string[3];
   byte[] rz = Resources.rz;
   byte[] data = Resources.data;
   var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString().ToUpper());
   var rz_p = Path.Combine(dir, Guid.NewGuid().ToString().ToUpper() + ".exe");
   var data_p = Path.Combine(dir, Guid.NewGuid().ToString().ToUpper());
   bool dirOK = false;
   if (!Directory.Exists(dir))
   {
    try
    {
     var d = Directory.CreateDirectory(dir);
     d.Attributes = FileAttributes.Hidden;
     dirOK = true;
    }
    catch
    {

    }
   }
   bool dataOK = false;
   if (dirOK)
   {
    try
    {
     File.WriteAllBytes(rz_p, rz);
     File.SetAttributes(rz_p, FileAttributes.Hidden);
     File.WriteAllBytes(data_p, data);
     File.SetAttributes(data_p, FileAttributes.Hidden);
     dataOK = true;
    }
    catch
    {
    }
   }
   bool unpacked = false;
   if (dataOK)
   {
    var psi = new ProcessStartInfo();
    psi.FileName = Path.GetFileName(rz_p);
    psi.Arguments = " e " + Path.GetFileName(data_p) + " *.*";
    psi.CreateNoWindow = true;
    psi.WindowStyle = ProcessWindowStyle.Hidden;
    psi.WorkingDirectory = dir;
    try
    {
     Process.Start(psi).WaitForExit();
    }
    catch
    {

    }
    finally
    {
     File.Delete(rz_p);
     File.Delete(data_p);
     unpacked = true;
    }
   }
   if (unpacked)
   {
    try
    {
     result[0] = dir;
     result[1] = Path.Combine(dir, "ilp.exe");
     result[2] = Path.Combine(dir, "tm.exe");
    }
    catch
    {

    }
   }
   return result;

  }
 }

}
