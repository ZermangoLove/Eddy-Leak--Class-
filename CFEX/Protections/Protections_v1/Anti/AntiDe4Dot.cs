/* Codded by: Eddy^CZ 2018 
   Date: 15.12.2018
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;

namespace Eddy_Protector_Protections.Protections.Anti
{
 public class AntiDe4Dot : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Protect assembly from automatical deobfuscating via De4Dot";
  public override string Id => Author + ".AntiDe4Dot";
  public override string Name => "Anti De4Dot";


  public override void Execute(Context ctx)
  {

   //ctx.RequestNative();

   foreach (var t in ctx.analyzer.targetCtx.methods_usercode)
   {
    var type = t.DeclaringType;
    DoAntiDeDot(ctx, type);
   }

  }


  public void DoAntiDeDot(Context ctx, TypeDef type)
  {
   List<InterfaceImplUser> interfaces1 = new List<InterfaceImplUser>();
   List<InterfaceImplUser> interfaces2 = new List<InterfaceImplUser>();

   List<TypeDef> types1 = new List<TypeDef>();
   List<TypeDef> types2 = new List<TypeDef>();

   for (int c = 0; c < 1; c++)
   {
    TypeDef fakeType0 = new TypeDefUser(ctx.generator.GenerateNewNameChinese(), ctx.generator.GenerateNewNameChinese(), ctx.CurrentModule.CorLibTypes.GetTypeRef("System", "Attribute"));
    fakeType0.Attributes = TypeAttributes.WindowsRuntime | TypeAttributes.StringFormatMask | TypeAttributes.Interface;
    fakeType0.BaseType = ctx.CurrentModule.GlobalType;
    fakeType0.ClassSize = ctx.generator.RandomUint();
    types1.Add(fakeType0);
    var i = new InterfaceImplUser(fakeType0);
    fakeType0.Interfaces.Add(i);
    interfaces1.Add(i);
   }
   for (int c = 0; c < 1; c++)
   {
    TypeDef fakeType0 = new TypeDefUser(ctx.generator.GenerateNewNameChinese(), ctx.generator.GenerateNewNameChinese(), ctx.CurrentModule.CorLibTypes.GetTypeRef("System", "Attribute"));
    fakeType0.Attributes = TypeAttributes.WindowsRuntime | TypeAttributes.StringFormatMask | TypeAttributes.Interface;
    fakeType0.ClassSize = ctx.generator.RandomUint();
    types2.Add(fakeType0);
    interfaces2.Add(new InterfaceImplUser(fakeType0));
   }

   var i1 = interfaces1.ToArray();
   var i2 = interfaces2.ToArray();
   var t1 = types1.ToArray();
   var t2 = types2.ToArray();

   var tt = type;

   for (int f = 0; f < t1.Length; f++)
   {
    for (int z = 0; z < i1.Length; z++)
    {
     for (int s = 0; s < i1.Length; s++)
     {
      t1[f].Interfaces.Add(i2[s]);
      t2[f].Interfaces.Add(i1[s]);
     }
     for (int s = 0; s < i2.Length; s++)
     {
      t2[f].Interfaces.Add(i1[s]);
      t1[f].Interfaces.Add(i2[s]);
     }
     t1[f].DeclaringType = tt;
     t2[f].DeclaringType = tt;
     t1[f].DeclaringType2 = t2[f].DeclaringType;
     t2[f].DeclaringType2 = t1[f].DeclaringType;
    }
   }
  }

 }
}
