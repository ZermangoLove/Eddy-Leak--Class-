using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Eddy_Protector_Protections.Protections.Renamer3
{

 public interface IRenaming
 {
  ModuleDefMD Rename(ModuleDefMD module);
 }

 public static class Utils
 {
  public static Context Context;
 }

 public class Renamer3 : ProtectionPhase
 {
  public override string Author => "";
  public override string Description => "";
  public override string Id => "";
  public override string Name => "Renamer(FirstPass)";

  public override void Execute(Context ctx)
  {

   Utils.Context = ctx;

   ModuleDefMD module = ctx.CurrentModule;

   IRenaming rnm = new NamespacesRenaming();

   module = rnm.Rename(module);

   rnm = new ClassesRenaming();

   module = rnm.Rename(module);

   rnm = new MethodsRenaming();

   module = rnm.Rename(module);

   rnm = new PropertiesRenaming();

   module = rnm.Rename(module);

   rnm = new FieldsRenaming();

   module = rnm.Rename(module);

   ctx.CurrentModule = module;
  }



  
 }
 public class FieldsRenaming : IRenaming
 {
  private static Dictionary<string, string> _names = new Dictionary<string, string>();

  public ModuleDefMD Rename(ModuleDefMD module)
  {
   ModuleDefMD moduleToRename = module;

   foreach (TypeDef type in moduleToRename.GetTypes())
   {
    if (type.IsGlobalModuleType)
     continue;

    foreach (var field in type.Fields)
    {
     string nameValue;
     if (_names.TryGetValue(field.Name, out nameValue))
      field.Name = nameValue;
     else
     {
      string newName = Utils.Context.generator.GenerateNewNameChinese();

      _names.Add(field.Name, newName);
      field.Name = newName;
     }
    }
   }

   return ApplyChangesToResources(moduleToRename);
  }

  private static ModuleDefMD ApplyChangesToResources(ModuleDefMD module)
  {
   ModuleDefMD moduleToRename = module;

   foreach (TypeDef type in moduleToRename.GetTypes())
   {
    if (type.IsGlobalModuleType)
     continue;

    foreach (MethodDef method in type.Methods)
    {
     if (method.Name != "InitializeComponent")
      continue;

     var instr = method.Body.Instructions;

     for (int i = 0; i < instr.Count - 3; i++)
     {
      if (instr[i].OpCode == OpCodes.Ldstr)
      {
       foreach (var item in _names)
       {
        if (item.Key == instr[i].Operand.ToString())
        {
         instr[i].Operand = item.Value;
        }
       }
      }
     }
    }
   }

   return moduleToRename;
  }
 }
 public class ClassesRenaming : IRenaming
 {
  private static Dictionary<string, string> _names = new Dictionary<string, string>();

  public ModuleDefMD Rename(ModuleDefMD module)
  {
   ModuleDefMD moduleToRename = module;

   foreach (TypeDef type in moduleToRename.GetTypes())
   {
    if (type.IsGlobalModuleType)
     continue;
    if (type.Name == "GeneratedInternalTypeHelper" || type.Name == "Resources" || type.Name == "Settings")
     continue;

    string nameValue;
    if (_names.TryGetValue(type.Name, out nameValue))
     type.Name = nameValue;
    else
    {
     string newName = Utils.Context.generator.GenerateNewNameChinese();

     _names.Add(type.Name, newName);
     type.Name = newName;
    }
   }

   return ApplyChangesToResources(moduleToRename);
  }

  private static ModuleDefMD ApplyChangesToResources(ModuleDefMD module)
  {
   ModuleDefMD moduleToRename = module;

   foreach (var resource in moduleToRename.Resources)
   {
    foreach (var item in _names)
    {
     if (resource.Name.Contains(item.Key))
     {
      resource.Name = resource.Name.Replace(item.Key, item.Value);
     }
    }
   }

   foreach (TypeDef type in moduleToRename.GetTypes())
   {
    foreach (var property in type.Properties)
    {
     if (property.Name != "ResourceManager")
      continue;

     var instr = property.GetMethod.Body.Instructions;

     for (int i = 0; i < instr.Count; i++)
     {
      if (instr[i].OpCode == OpCodes.Ldstr)
      {
       foreach (var item in _names)
       {
        if (instr[i].Operand.ToString().Contains(item.Key))
         instr[i].Operand = instr[i].Operand.ToString().Replace(item.Key, item.Value);
       }
      }
     }
    }
   }

   return moduleToRename;
  }
 }

 public class MethodsRenaming : IRenaming
 {
  public ModuleDefMD Rename(ModuleDefMD module)
  {
   ModuleDefMD moduleToRename = module;

   foreach (TypeDef type in moduleToRename.GetTypes())
   {
    if (type.IsGlobalModuleType)
     continue;

    if (type.Name == "GeneratedInternalTypeHelper")
     continue;

    foreach (MethodDef method in type.Methods)
    {
     if (!method.HasBody)
      continue;

     if (method.Name == ".ctor" || method.Name == ".cctor")
      continue;

     method.Name = Utils.Context.generator.GenerateNewNameChinese();
    }
   }

   return moduleToRename;
  }
 }

 public class NamespacesRenaming : IRenaming
 {
  private static Dictionary<string, string> _names = new Dictionary<string, string>();

  public ModuleDefMD Rename(ModuleDefMD module)
  {
   ModuleDefMD moduleToRename = module;

   foreach (TypeDef type in moduleToRename.GetTypes())
   {
    if (type.IsGlobalModuleType)
     continue;

    if (type.Namespace == "")
     continue;

    string nameValue;
    if (_names.TryGetValue(type.Namespace, out nameValue))
     type.Namespace = nameValue;
    else
    {
     string newName = Utils.Context.generator.GenerateNewNameChinese();

     _names.Add(type.Namespace, newName);
     type.Namespace = newName;
    }
   }

   return ApplyChangesToResources(moduleToRename);
  }

  private static ModuleDefMD ApplyChangesToResources(ModuleDefMD module)
  {
   ModuleDefMD moduleToRename = module;

   foreach (var resource in moduleToRename.Resources)
   {
    foreach (var item in _names)
    {
     if (resource.Name.Contains(item.Key))
     {
      resource.Name = resource.Name.Replace(item.Key, item.Value);
     }
    }
   }

   foreach (TypeDef type in moduleToRename.GetTypes())
   {
    foreach (var property in type.Properties)
    {
     if (property.Name != "ResourceManager")
      continue;

     var instr = property.GetMethod.Body.Instructions;

     for (int i = 0; i < instr.Count; i++)
     {
      if (instr[i].OpCode == OpCodes.Ldstr)
      {
       foreach (var item in _names)
       {
        if (instr[i].ToString().Contains(item.Key))
         instr[i].Operand = instr[i].Operand.ToString().Replace(item.Key, item.Value);
       }
      }
     }
    }
   }

   return moduleToRename;
  }
 }

 public class PropertiesRenaming : IRenaming
 {
  public ModuleDefMD Rename(ModuleDefMD module)
  {
   ModuleDefMD moduleToRename = module;

   foreach (TypeDef type in moduleToRename.GetTypes())
   {
    if (type.IsGlobalModuleType)
     continue;

    foreach (var property in type.Properties)
    {
     property.Name = Utils.Context.generator.GenerateNewNameChinese();
    }
   }

   return moduleToRename;
  }
 }

}
