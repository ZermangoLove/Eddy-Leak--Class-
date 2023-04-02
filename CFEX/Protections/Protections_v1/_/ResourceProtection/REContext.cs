using dnlib.DotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using Confuser.DynCipher;

namespace Eddy_Protector.Protections.ResourceProtection
{
 internal class REContext
 {
  public Context Context;

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
