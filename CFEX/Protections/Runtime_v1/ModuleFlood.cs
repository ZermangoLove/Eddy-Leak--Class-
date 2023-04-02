using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Threading;

namespace Eddy_Protector_Runtime
{
 internal static class ModuleFlood
 {
  private static void Initialize0()
  {
   if (Debugger.IsAttached || Debugger.IsLogging())
   {
    Process.GetCurrentProcess().Kill();
   }
   
  }
 }
}
