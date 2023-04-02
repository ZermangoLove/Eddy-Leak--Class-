using Eddy_Protector.Core.Poly;
using Mono.Cecil;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Eddy_Protector.Protections.CtorProxy
{
 class ProtectionContext
 {
  public bool isNative;
  public Dictionary<string, TypeDefinition> delegates;
  public Dictionary<string, FieldDefinition> fields;
  public Dictionary<string, MethodDefinition> bridges;
  public MethodDefinition proxy;

  public Range nativeRange;
  public MethodDefinition nativeDecr;
  public Expression exp;
  public Expression invExp;
  public uint key;

  public List<DelegateContext> txts;
  public TypeReference mcd;
  public TypeReference v;
  public TypeReference obj;
  public TypeReference ptr;
 }
}
