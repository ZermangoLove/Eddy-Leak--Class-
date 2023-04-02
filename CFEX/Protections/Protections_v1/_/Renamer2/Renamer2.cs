using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector.Core;
using dnlib.DotNet;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections.ObjectModel;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace Eddy_Protector.Protections.Renamer2
{
 class Renamer2 : ProtectionPhase
 {
  public override string Author => Engine.Author;
  public override string Description => "Rename all in assembly based on SNDConfuser";
  public override string Id => Author + ".Renamer2";
  public override string Name => "Renamer2";
  public override void Execute(Context ctx)
  {
   var ren = new Renamer();
   ren.Protect(ctx);
  }


  public static class Checker
  {
   public static bool checkType(TypeDef td)
   {
    return !td.IsRuntimeSpecialName && !td.IsSpecialName && !td.IsNestedFamilyOrAssembly && !td.IsNestedFamilyAndAssembly;
   }
   public static bool checkMethod(MethodDef md)
   {
    if (!md.IsConstructor && !md.IsFamilyAndAssembly && !md.IsSpecialName && !md.IsRuntimeSpecialName && !md.IsRuntime && !md.IsFamily)
    {
     if (md.DeclaringType.BaseType != null)
     {
      if (!md.DeclaringType.BaseType.Name.Contains("Delegate"))
       return true;
     }
     return false;

    }
    return false;
   }
   public static bool checkField(FieldDef fd)
   {
    return !fd.IsFamilyOrAssembly && !fd.IsSpecialName && !fd.IsRuntimeSpecialName && !fd.IsFamily && !fd.DeclaringType.IsEnum && !fd.DeclaringType.BaseType.Name.Contains("Delegate");
   }
   public static bool checkProperty(PropertyDef pd)
   {
    return !pd.IsSpecialName && !pd.IsRuntimeSpecialName && !pd.DeclaringType.Name.Contains("AnonymousType");
   }
   public static bool checkEvent(EventDef ed)
   {
    return !ed.IsSpecialName && !ed.IsRuntimeSpecialName;
   }
   public static bool isForm(AssemblyDef asm)
   {
    bool result = false;
    foreach (ModuleDef current in asm.Modules)
    {
     foreach (TypeDef current2 in current.Types)
     {
      foreach (TypeDef current3 in current2.NestedTypes)
      {
       foreach (MethodDef current4 in current3.Methods)
       {
        if (current4.Name == "InitializeComponent")
        {
         result = true;
        }
       }
      }
      foreach (MethodDef current5 in current2.Methods)
      {
       if (current5.Name == "InitializeComponent")
       {
        result = true;
       }
      }
     }
    }
    return result;
   }
  }

  class Renamer
  {
   private static Dictionary<string, string> TypeDefNames = new Dictionary<string, string>();
   private static Collection<TypeDef> namespaces = new Collection<TypeDef>();
   private static List<string> NamespaceNames = new List<string>();
   private Context context;
   public void Protect(Context ctx)
   {
    context = ctx;
    ModuleDef moduleDef = ctx.CurrentModule;

    for (int j = 0; j < moduleDef.Types.Count; j++)
    {

     TypeDef td = moduleDef.Types[j];

     if (td.DeclaringType == moduleDef.GlobalType)
      continue;

     IterateType(td, ctx.CurrentModule.Assembly);
    }

    //foreach (var t in ctx.analyzer.target_types)
    //{
    // IterateType(t, ctx.CurrentModule.Assembly);
    //}

    moduleDef.EntryPoint.Name = ctx.generator.GenerateNewNameChinese();
   }
   private void IterateType(TypeDef td, AssemblyDef asm)
   {
    if (td.HasNestedTypes)
    {
     for (int i = 0; i < td.NestedTypes.Count; i++)
      IterateType(td.NestedTypes[i], asm);
    }

    if (!NamespaceNames.Contains(td.Namespace))
    {
     NamespaceNames.Add(td.Namespace);
     namespaces.Add(td);

     td.Namespace = context.generator.GenerateNewNameChinese();

    }
    else
    {
     namespaces.Add(td);
    }

    if (Checker.checkType(td))
    {
     string text;
     if (td.Name != "<Module>")
      text = context.generator.GenerateNewNameChinese();
     else
      text = context.generator.GenerateNewNameChinese();

     if (!TypeDefNames.ContainsKey(td.Name))
      TypeDefNames.Add(td.Name, text);
     //
     if (td.BaseType == null) return;
     if (td.BaseType.Name.Contains("Form"))
     {
      string tmpp = "";
      foreach (Resource res in asm.ManifestModule.Resources)
      {
       if (res.Name.Contains(td.Name))
       {
        tmpp = td.Name;
        string tmpN = res.Name.Replace(".resources", "");
        res.Name = tmpN.Replace(td.Name, text) + ".resources";
       }

      }
      foreach (MethodDef mDef in td.Methods)
      {
       //if (!mDef.HasBody && !mDef.FullName.Contains("getRes")) continue;
       foreach (Instruction instr in mDef.Body.Instructions)
       {
        if (instr.OpCode == OpCodes.Ldstr)
        {
         if (instr.Operand.ToString().Contains(tmpp))
          instr.Operand = instr.Operand.ToString().Replace(td.Name, text);
        }
       }
      }
     }
     ///
     td.Name = text;

     for (int i = 0; i < td.Methods.Count; i++)
     {
      MethodDef md = td.Methods[i];
      ChangeMethod(md);
     }
     for (int i = 0; i < td.Fields.Count; i++)
     {
      FieldDef fd = td.Fields[i];
      ChangeField(fd);
     }
     for (int i = 0; i < td.Events.Count; i++)
     {
      EventDef ed = td.Events[i];
      ChangeEvent(ed);
     }
     for (int i = 0; i < td.Properties.Count; i++)
     {
      PropertyDef pd = td.Properties[i];
      ChangeProperty(pd);
     }
    }

   }
   private void ChangeMethod(MethodDef md)
   {

    if (Checker.checkMethod(md))
    {
     md.Name = context.generator.GenerateNewNameChinese();
     foreach (ParamDef current in md.ParamDefs)
     {
      current.Name = context.generator.GenerateNewNameChinese();
     }
     if (md.HasBody && md.Body.HasVariables)
     {
      foreach (var current2 in md.Body.Variables)
      {
       current2.Name = context.generator.GenerateNewNameChinese();
      }
     }
     md.Attributes = (MethodAttributes.Public | md.Attributes);
    }
   }
   private void ChangeField(FieldDef fd)
   {
    if (Checker.checkField(fd))
    {
     fd.Name = context.generator.GenerateNewNameChinese();
    }
   }
   private void ChangeEvent(EventDef ed)
   {
    if (Checker.checkEvent(ed))
    {
     ed.Name = context.generator.GenerateNewNameChinese();
    }
   }
   private void ChangeProperty(PropertyDef pd)
   {
    if (Checker.checkProperty(pd))
    {
     pd.Name = context.generator.GenerateNewNameChinese();
    }
   }
  }
 }
}
