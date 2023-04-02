using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core.Poly;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Eddy_Protector_Core.Core.Poly.Visitors;

namespace Eddy_Protector_Protections.Protections.Constants2
{
 public struct Conster
 {
  public MethodDefinition conster;
  public long key0;
  public long key1;
  public long key2;
  public int key3;
  public Instruction keyInst;
 }
 public class ProtectionContext
 {
  public List<byte[]> dats;
  public Dictionary<object, int> dict;
  public int idx = 0;
  public uint key;
  public byte[] keyBuff = new byte[32];

  public int resKey;
  public string resId;
  public Conster[] consters;

  public Instruction keyInst;

  public bool isDyn;
  public Expression exp;
  public Expression invExp;

 }
}
