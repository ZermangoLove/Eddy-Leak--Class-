using Eddy_Protector_Ciphering;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Eddy_Protector_Protections.Protections.Compressor
{
 internal enum Mode
 {
  Normal,
  Dynamic
 }

 public interface IKeyDeriver
 {
  void Init(RandomGenerator random);
  uint[] DeriveKey(uint[] a, uint[] b);
  IEnumerable<Instruction> EmitDerivation(MethodDef method, Local dst, Local src);
 }
}
