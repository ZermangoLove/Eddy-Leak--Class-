using Protector.Properties;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Protector.Protections.NativePacker
{
 class NativePackerProtection
 {
  /// <summary>
  /// 0 = native , 1 = net
  /// </summary>
  /// <param name="input_assembly"></param>
  /// <param name="native_or_net"></param>
  /// <returns></returns>
  public byte[] Protect(byte[] input_assembly, int native_or_net, ProtectorContext context)
  {
   byte[] result = null;
   string tmp_fld = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
   if (Directory.CreateDirectory(tmp_fld).Exists)
   {
    string rz_pth = Path.Combine(tmp_fld, Guid.NewGuid().ToString() + ".exe");
    string rz_arch_pth = Path.Combine(tmp_fld, Guid.NewGuid().ToString());
    File.WriteAllBytes(rz_pth, Resources.rz);
    File.WriteAllBytes(rz_arch_pth, Resources.native_crypter);

    ProcessStartInfo pi = new ProcessStartInfo();
    pi.WorkingDirectory = tmp_fld;
    pi.WindowStyle = ProcessWindowStyle.Hidden;
    pi.CreateNoWindow = true;
    pi.FileName = rz_pth;
    pi.Arguments = " e " + Path.GetFileName(rz_arch_pth) + " *.*";
    Process.Start(pi).WaitForExit();

    string net_packer = Path.Combine(tmp_fld, "NativeCrypter.exe");

    if (File.Exists(net_packer))
    {

     string in_file = Path.Combine(tmp_fld, Guid.NewGuid().ToString());
     string out_file = Path.Combine(tmp_fld, Guid.NewGuid().ToString());

     string blobKey = Convert.ToBase64String(BitConverter.GetBytes(context.BlobKey));

     File.WriteAllBytes(in_file, input_assembly);

     if (File.Exists(in_file))
     {
      ProcessStartInfo pi_s = new ProcessStartInfo();
      pi_s.FileName = net_packer;
      pi_s.WorkingDirectory = tmp_fld;
      pi_s.CreateNoWindow = true;
      pi_s.WindowStyle = ProcessWindowStyle.Hidden;

      if(native_or_net == 0)//native
      {
       pi_s.Arguments = in_file + " " + out_file + " " +"Stub_native.exe";
      }
      if (native_or_net == 1)//net
      {
       pi_s.Arguments = in_file + " " + out_file + " " +"Stub_net.exe" + " " + blobKey;
      }
  
      Process.Start(pi_s).WaitForExit();

      if (File.Exists(out_file))
      {

       string pe_packer =  Path.Combine(tmp_fld, "pepacker.exe");
       string pe_out_file = Path.Combine(tmp_fld, Guid.NewGuid().ToString());

       ProcessStartInfo pi_pe = new ProcessStartInfo();
       pi_pe.FileName = pe_packer;
       pi_pe.WorkingDirectory = tmp_fld;
       pi_pe.CreateNoWindow = true;
       pi_pe.WindowStyle = ProcessWindowStyle.Hidden;
       pi_pe.Arguments = out_file + " " + pe_out_file;

       Process.Start(pi_pe).WaitForExit();


       result = File.ReadAllBytes(pe_out_file);

       if (result != null)
       {
        Directory.Delete(tmp_fld, true);
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
