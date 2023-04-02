using dnlib.DotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Ciphering;

namespace Protector.Protections.ResourcesProtect
{
 internal class REContext
 {
  public ProtectorContext Context;

  public FieldDef DataField;
  public TypeDef DataType;
  public IDynCipherService DynCipher;
  public MethodDef InitMethod;
  public Mode Mode;
  public IEncodeMode ModeHandler;
  public ModuleDef Module;
  public RandomGenerator Random;

  public List<MethodDef>RuntimeMethods = new List<MethodDef>();
 }
}
