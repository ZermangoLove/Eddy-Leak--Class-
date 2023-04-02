using Confuser.DynCipher;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Eddy_Protector.Protections.Compressor
{
 internal enum Mode
 {
  Normal,
  Dynamic
 }

 internal interface IKeyDeriver
 {
  void Init(RandomGenerator random);
  uint[] DeriveKey(uint[] a, uint[] b);
  IEnumerable<Instruction> EmitDerivation(MethodDef method, Local dst, Local src);
 }
}
