using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


using Protector.Protections;
using dnlib.DotNet;
using Protector.Helpers;
using dnlib.DotNet.Writer;
using System.IO;
using Protector.Protections.JitHook;

namespace Protector.Protections.AntiTamper
{
 class AntiTamperProtection
 {
  public static bool VirtualizeAntitamper = false;
  public static bool VirtualizeCctor = false;
  public static bool VirtualizeAntitamperAndCctor = false;
  public static int AntitampersUsed = 0;
  /// <summary>
  /// 
  /// </summary>
  /// <param name="vm">0 = No virtualize Antitamp, 1 = Virtualize AntiTamp, 2 = VirtualizeCctor</param>
  public AntiTamperProtection(int vm)
  {
   switch (vm)
   {
    case 0:
     VirtualizeAntitamper = false;
     return;
    case 1:
     VirtualizeAntitamper = true;
     return;
    case 2:
     VirtualizeCctor = true;
     return;
    case 3:
     VirtualizeAntitamperAndCctor = true;
     return;
   }
  }

  public byte[] AddAntiTamper(ModuleDef module, ProtectorContext context)
  {

   //context.CurrentModuleWriterListener = new ModuleWriterListener();
   context.CurrentModuleWriterOptions = new ModuleWriterOptions(module, context.CurrentModuleWriterListener);

   List<MethodDef> targets = new List<MethodDef>();


   //module = new Antidump.AntidumpProtection().AddAntidump(module, context);

   targets = SearchTargets(module);


   //IModeHandler jitmode = new JITMode();
   //module = jitmode.HandleInject(module, context);
   //jitmode.HandleMD(targets, context);
   //return UpdateModule(module, context);



   var normal = new NormalMode();
   IModeHandler mode = normal;
   module = mode.HandleInject(module, context);
   mode.HandleMD(targets, context);

   //foreach (var m in context.AntiTamperMethods)
   //{
    
   //}

   return UpdateModule(module, context);
  }

  public List<MethodDef> SearchTargets(ModuleDef module)
  {
   List<MethodDef> targets = new List<MethodDef>();

   foreach (var t in module.GetTypes())
   {
    foreach (var m in t.Methods)
    {
     if (!m.IsConstructor)
     {
      targets.Add(m);
     }
    }
   }
   return targets;
  }

  public byte[] UpdateModule(ModuleDef module, ProtectorContext ctx)
  {
   MemoryStream output = new MemoryStream();
   ctx.CurrentModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;
   //ctx.CurrentModuleWriterOptions.MetaDataOptions.Flags = MetaDataFlags.PreserveAll;

   
   if (ctx.CurrentModuleWriterOptions is ModuleWriterOptions)
   {
    try
    {
     module.Write(output, (ModuleWriterOptions)ctx.CurrentModuleWriterOptions);
    }
    catch(Exception e)
    {
     
    }
    
   }
   return output.ToArray();
  }

 }
}
