using System;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;
using System.Collections.Generic;

namespace Eddy_Protector_Protections.Protections.Renamer
{
 public class Renamer : ProtectionPhase
 {
  public override string Author => "EddyCZ";
  public override string Description => "Rename all in assembly";
  public override string Id => "EddyCZ.Renamer";
  public override string Name => "Renamer";

  public Context ctxx;

  public override void Execute(Context ctx)
  {
   ctxx = ctx;
   DoRename(ctx.CurrentModule);
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

   string namespaceNewName = ctxx.generator.GenerateNewNameChinese();
   foreach (TypeDef type in module.Types)
   {

    bool canRenameType;
    if (typeRename.TryGetValue(type, out canRenameType))
    {
     if (canRenameType)
      InternalRename(type);

    }
    else
     InternalRename(type);
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
  //else
  //{
  // foreach (var typeItem in typeRename)
  // {
  //  if (typeItem.Value)
  //   InternalRename(typeItem.Key);
  // }
  // foreach (var methodItem in methodRename)
  // {
  //  if (methodItem.Value)
  //   InternalRename(methodItem.Key);
  // }
  // foreach (var fieldItem in fieldRename)
  // {
  //  if (fieldItem.Value)
  //   InternalRename(fieldItem.Key);
  // }
  //}

  public void InternalRename(TypeDef type)
  {
   string randString = ctxx.generator.GenerateNewNameChinese();
   while (typeNewName.Contains(randString))
    randString = ctxx.generator.GenerateNewNameChinese();
   typeNewName.Add(randString);
   type.Name = randString;
  }

  public void InternalRename(MethodDef method)
  {
   string randString = ctxx.generator.GenerateNewNameChinese();
   while (methodNewName.Contains(randString))
    randString = ctxx.generator.GenerateNewNameChinese();
   methodNewName.Add(randString);
   method.Name = randString;
  }

  public void InternalRename(FieldDef field)
  {
   string randString = ctxx.generator.GenerateNewNameChinese();
   while (fieldNewName.Contains(randString))
    randString = ctxx.generator.GenerateNewNameChinese();
   fieldNewName.Add(randString);
   field.Name = randString;
  }



  #region OLDRENAMER
  //public void DoRename(Context ctx)
  //{
  //	var renamer = ctx.generator;

  //	foreach (TypeDef t in ctx.CurrentModule.GetTypes())
  //	{
  //		if (t.IsGlobalModuleType)
  //		{
  //			continue;
  //		}
  //		if (t.IsAbstract && t.IsSealed)
  //		{
  //			continue;
  //		}
  //		t.Namespace = renamer.GenerateNewNameChinese();
  //		t.Name = renamer.GenerateNewNameChinese();

  //		foreach (MethodDef m in t.Methods)
  //		{
  //			if (m.IsConstructor || m.DeclaringType.IsForwarder)
  //			{
  //				continue;
  //			}
  //			m.Name = renamer.GenerateNewNameChinese();

  //			foreach (ParamDef p in m.ParamDefs)
  //			{
  //				p.Name = renamer.GenerateNewNameChinese();
  //			}

  //			if (m.HasBody && m.Body.HasVariables)
  //			{
  //				foreach (var vari in m.Body.Variables)
  //				{
  //					vari.Name = renamer.GenerateNewNameChinese();
  //				}
  //			}
  //		}

  //		foreach (FieldDef f in t.Fields)
  //		{
  //			if ((f.IsStatic || f.IsLiteral || f.DeclaringType.IsEnum))
  //			{
  //				continue;
  //			}
  //			f.Name = renamer.GenerateNewNameChinese();
  //		}

  //		foreach (EventDef e in t.Events)
  //		{
  //			e.Name = renamer.GenerateNewNameChinese();
  //		}
  //		foreach (PropertyDef p in t.Properties)
  //		{
  //			p.Name = renamer.GenerateNewNameChinese();
  //		}
  //	}
  //}

  #endregion


 }
}
