using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Protector.Protections.ResourcesProtect
{
 internal interface IEncodeMode
 {
  IEnumerable<Instruction> EmitDecrypt(MethodDef init, REContext ctx, Local block, Local key);
  uint[] Encrypt(uint[] data, int offset, uint[] key);
 }
}
