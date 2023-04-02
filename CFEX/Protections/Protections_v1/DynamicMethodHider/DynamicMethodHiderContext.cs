using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mono.Cecil;
using System.Reflection;

namespace Eddy_Protector_Protections.Protections.DynamicMethodHider
{
 class DynamicMethodHiderContext
 {
  /* < ---- YOUR ASSEMBLY ----> */
  public AssemblyDefinition assemblyCecil;
  public Assembly assemblyReflection;

  /* < ---- LOADER ----> */
  public AssemblyDefinition loaderAssemblyCecil;
  public Assembly loaderAssemblyReflection;

  /* < ---- DynamicHider ----> */
  public MethodReference openLoader;
  public MethodReference invoker;
  public FieldReference LoadObjectProtected;
  public FieldReference loader;


  /* < ---- RSA ----> */
  public string publicKey;
  public string privateKey;

 }
}
