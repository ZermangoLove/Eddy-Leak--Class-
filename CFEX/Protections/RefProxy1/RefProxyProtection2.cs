using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;

namespace Protector.Protections.RefProxy2
{
 class RuntimeRefProxy2
 {
  public void DoRefProxy2(MethodDef method, ProtectorContext ctx)
  {
   var rf = new RPNormal();

   rf.Execute(method, ctx);

  }
 }
}
