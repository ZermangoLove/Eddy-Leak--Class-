using System;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using System.Collections.Generic;

namespace Protector.Protections.Renamer
{
 class RenamerProtection
 {
  public ProtectorContext ctxx;

  public ModuleDef StartRenaming(ModuleDef module, ProtectorContext ctx)
  {
   ctxx = ctx;
   DoRename((ModuleDefMD)module);
   return module;
  }


  static Dictionary<TypeDef, bool> typeRename = new Dictionary<TypeDef, bool>();
  static List<string> typeNewName = new List<string>();
  static Dictionary<MethodDef, bool> methodRename = new Dictionary<MethodDef, bool>();
  static List<string> methodNewName = new List<string>();
  static Dictionary<FieldDef, bool> fieldRename = new Dictionary<FieldDef, bool>();
  static List<string> fieldNewName = new List<string>();

  public void Rename(TypeDef type, bool canRename = true)
  {
   if (typeRename.ContainsKey(type))
    typeRename[type] = canRename;
   else
    typeRename.Add(type, canRename);
  }

  public void Rename(MethodDef method, bool canRename = true)
  {
   if (methodRename.ContainsKey(method))
    methodRename[method] = canRename;
   else
    methodRename.Add(method, canRename);
  }

  public void Rename(FieldDef field, bool canRename = true)
  {
   if (fieldRename.ContainsKey(field))
    fieldRename[field] = canRename;
   else
    fieldRename.Add(field, canRename);
  }

  public void DoRename(ModuleDefMD module)
  {

   string namespaceNewName = ctxx.random_generator.GenerateString();
   foreach (TypeDef type_main in module.Types)
   {

    foreach(var type in type_main.GetTypes())
    {

     InternalRename(type);

     //bool canRenameType;
     //if (typeRename.TryGetValue(type, out canRenameType))
     //{
     // if (canRenameType)
     //  InternalRename(type);

     //}
     //else
     // InternalRename(type);
     type.Namespace = namespaceNewName;
     foreach (MethodDef method in type.Methods)
     {
      bool canRenameMethod;
      if (methodRename.TryGetValue(method, out canRenameMethod))
      {
       if (canRenameMethod && !method.IsConstructor && !method.IsSpecialName)
        InternalRename(method);
      }
      else if (!method.IsConstructor && !method.IsSpecialName)
       InternalRename(method);
     }
     methodNewName.Clear();
     foreach (FieldDef field in type.Fields)
     {
      bool canRenameField;
      if (fieldRename.TryGetValue(field, out canRenameField))
      {
       if (canRenameField)
        InternalRename(field);
      }
      else
       InternalRename(field);
     }
     fieldNewName.Clear();
    }
   }

  }

  public void InternalRename(TypeDef type)
  {
   string randString = ctxx.random_generator.GenerateString();
   while (typeNewName.Contains(randString))
    randString = ctxx.random_generator.GenerateString();
   typeNewName.Add(randString);
   type.Name = randString;
  }

  public void InternalRename(MethodDef method)
  {
   string randString = ctxx.random_generator.GenerateString();
   while (methodNewName.Contains(randString))
    randString = ctxx.random_generator.GenerateString();
   methodNewName.Add(randString);
   method.Name = randString;
  }

  public void InternalRename(FieldDef field)
  {
   string randString = ctxx.random_generator.GenerateString();
   while (fieldNewName.Contains(randString))
    randString = ctxx.random_generator.GenerateString();
   fieldNewName.Add(randString);
   field.Name = randString;
  }


 }
}
