using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Eddy_Protector_Protections.Protections.Anti
{
 public class AntiDebug : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "AntiDebug Protection";
  public override string Id => Author+".AntiDebug";
  public override string Name => "AntiDebug";

  enum AntiMode
  {
   Safe,
   Win32,
   Antinet
  }

  public override void Execute(Context ctx)
  {
   for (int a = 0; a < new Random().Next(5,10); a++)
   {
    InjectAntiDebug(ctx);
   }
  }

  public void InjectAntiDebug(Context ctx)
  {
   AntiMode mode = AntiMode.Win32;

   TypeDef rtType;
   TypeDef attr = null;
   const string attrName = "System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptionsAttribute";
   switch (mode)
   {
    case AntiMode.Safe:
     rtType = Utils.GetRuntimeType("Eddy_Protector_Runtime.AntiDebugSafe");
     break;
    case AntiMode.Win32:
     rtType = Utils.GetRuntimeType("Eddy_Protector_Runtime.AntiDebugWin32");
     break;
    case AntiMode.Antinet:
     rtType = Utils.GetRuntimeType("Eddy_Protector_Runtime.AntiDebugAntinet");

     attr = Utils.GetRuntimeType(attrName);
     ctx.CurrentModule.Types.Add(attr = InjectHelper.Inject(attr, ctx.CurrentModule));
     break;
    default:
     throw new NotImplementedException();
   }

   IEnumerable<IDnlibDef> members = InjectHelper.Inject(rtType, ctx.CurrentModule.GlobalType, ctx.CurrentModule);

   MethodDef cctor = ctx.CurrentModule.GlobalType.FindOrCreateStaticConstructor();
   var init = (MethodDef)members.Single(method => method.Name == "Initialize");
   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));

   init.Name = ctx.generator.GenerateNewNameChinese();
   ctx.runtime_protect.runtime_refproxy2.DoRefProxy2(init,ctx);
   //ctx.analyzer.targetCtx.methods_virtualize.Add(init);
   //ctx.runtime_protect.runtime_refproxy.DeRefProxy(init, ctx);
   //ctx.runtime_protect.runtime_controlflow1.DoControlFlow(init, ctx);


   foreach (IDnlibDef member in members)
   {

    bool ren = true;
    if (member is MethodDef)
    {
     var method = (MethodDef)member;

     method.Name = ctx.generator.GenerateNewNameChinese();
     //ctx.runtime_protect.runtime_controlflow1.DoControlFlow(method, ctx);
     //ctx.runtime_protect.runtime_refproxy.DeRefProxy(method, ctx);

     if (method.Access == MethodAttributes.Public)
      method.Access = MethodAttributes.Assembly;
     if (!method.IsConstructor)
      method.IsSpecialName = false;
     else
      ren = false;

     CustomAttribute ca = method.CustomAttributes.Find(attrName);
     if (ca != null)
      ca.Constructor = attr.FindMethod(".ctor");
    }
    else if (member is FieldDef)
    {
     var field = (FieldDef)member;
     if (field.Access == FieldAttributes.Public)
      field.Access = FieldAttributes.Assembly;
     if (field.IsLiteral)
     {
      field.DeclaringType.Fields.Remove(field);
      continue;
     }
    }
   }
  }

 }
}
