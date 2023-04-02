using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

using Protector.Properties;
using System.Diagnostics;

namespace Protector.Protections.Shrinker
{
 class Shrinker
 {
  public byte[] Shrink(byte[] input_assembly)
  {
   byte[] result = null;
   string tmp_fld = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
   if(Directory.CreateDirectory(tmp_fld).Exists)
   {
    string rz_pth = Path.Combine(tmp_fld,Guid.NewGuid().ToString()+".exe");
    string rz_arch_pth = Path.Combine(tmp_fld, Guid.NewGuid().ToString());
    File.WriteAllBytes(rz_pth, Resources.rz);
    File.WriteAllBytes(rz_arch_pth, Resources.net_shrink);

    ProcessStartInfo pi = new ProcessStartInfo();
    pi.WorkingDirectory = tmp_fld;
    pi.WindowStyle = ProcessWindowStyle.Hidden;
    pi.CreateNoWindow = true;
    pi.FileName = rz_pth;
    pi.Arguments = " e " + Path.GetFileName(rz_arch_pth) + " *.*";
    Process.Start(pi).WaitForExit();

    string net_packer = Path.Combine(tmp_fld, "net-packer.exe");

    if(File.Exists(net_packer))
    {

     string in_file = Path.Combine(tmp_fld, Guid.NewGuid().ToString());
     string out_file = Path.Combine(tmp_fld, Guid.NewGuid().ToString());


     File.WriteAllBytes(in_file, input_assembly);

     if(File.Exists(in_file))
     {
      ProcessStartInfo pi_s = new ProcessStartInfo();
      pi_s.FileName = net_packer;
      pi_s.WorkingDirectory = tmp_fld;
      pi_s.CreateNoWindow = true;
      pi_s.WindowStyle = ProcessWindowStyle.Hidden;
      pi_s.Arguments = in_file + " " + out_file;
      Process.Start(pi_s).WaitForExit();

      if(File.Exists(out_file))
      {
       result =  File.ReadAllBytes(out_file);

       if(result != null)
       {
        Directory.Delete(tmp_fld,true);
        return result;
       }
      }

     }


    }

   }


   return null;
  }
 }
}
