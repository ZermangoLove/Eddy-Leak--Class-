using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet;

namespace Eddy_Protector.Protections.TypeDecomposer
{
 class TypeDecomposerProtection : ProtectionPhase
 {
  public override string Author => "";
  public override string Description => "";
  public override string Id => "";
  public override string Name => "";


  public override void Execute(Context ctx)
  {
   foreach (var m in ctx.analyzer.targetCtx.methods_usercode)
   {
    if (m.Name == "InitializeComponent") continue;
    if (m.IsConstructor) continue;

    TypeDef oldType = m.DeclaringType;

    TypeDef newType = new TypeDefUser(ctx.generator.GenerateNewName(), ctx.CurrentModule.CorLibTypes.Object.TypeDefOrRef);

    newType.Attributes = oldType.Attributes;

    m.DeclaringType = newType;

    ctx.CurrentModule.Types.Add(newType);

    //ctx.CurrentModule.Types.Remove(oldType);

   }
  }
 }
}
