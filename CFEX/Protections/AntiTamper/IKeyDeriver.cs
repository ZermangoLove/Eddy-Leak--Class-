using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Eddy_Protector_Ciphering;
using Protector.Protections;

namespace Protector.Protections.AntiTamper
{
 internal enum Mode
 {
  Normal,
  Dynamic
 }

 internal interface IKeyDeriver
 {
  void Init(ProtectorContext ctx, RandomGenerator random);
  uint[] DeriveKey(uint[] a, uint[] b);
  IEnumerable<Instruction> EmitDerivation(MethodDef method, ProtectorContext ctx, Local dst, Local src);
 }
}