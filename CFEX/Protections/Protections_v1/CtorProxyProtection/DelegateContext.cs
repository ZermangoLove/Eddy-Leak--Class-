using Mono.Cecil;
using Mono.Cecil.Cil;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Eddy_Protector_Protections.Protections.CtorProxy
{
 public class DelegateContext
 {
  public MethodBody bdy;
  public Instruction inst;
  public FieldDefinition fld;
  public TypeDefinition dele;
  public MethodReference mtdRef;
  public MetadataToken token;
 }
}
