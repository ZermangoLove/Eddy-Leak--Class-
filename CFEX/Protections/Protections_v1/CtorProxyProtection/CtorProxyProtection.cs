using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;

using Mono.Cecil;
using Eddy_Protector_Core.Core.OldConfuser;
using Mono.Cecil.Cil;
using Eddy_Protector_Core.Core.Poly;
using Mono.Cecil.Metadata;

namespace Eddy_Protector_Protections.Protections.CtorProxy
{
 public class CtorProxyProtection : ProtectionPhase
 {
  public override string Author => "Eddy^CZ";
  public override string Description => "Hide calls in constructors to proxy";
  public override string Id => "Eddy^CZ.CtorProxy";
  public override string Name => "CtorProxy";

  Dictionary<ModuleDefinition, ProtectionContext> txts = new Dictionary<ModuleDefinition, ProtectionContext>();
  ModuleDefinition mod;
  Context Context;

  public override void Execute(Context ctx)
  {

   foreach(var type in ctx.analyzer.targetCtx.Module_mono.GetAllTypes())
   {
    foreach(var m in type.Methods)
    {
     if(!ctx.analyzer.targetCtx.targets_mono.Contains(m))
     {
      ctx.analyzer.targetCtx.targets_mono.Add(m);
     }
    }
   }

   Initialize(ctx);
   FirstPhase(ctx);
   SecondPhase(ctx);
   ThirdPhase();

   ctx.metaDataProcessor.BeforeBuildModule += new MetadataProcessor.MetadataProcess(delegate (MetadataProcessor.MetadataAccessor accessor)
   {
    FirstFinalPhase(accessor, ctx);
    
   });

   ctx.metaDataProcessor.AfterWriteTables += new MetadataProcessor.MetadataProcess(delegate (MetadataProcessor.MetadataAccessor accessor)
   {
    SecondFinalPhase(accessor, ctx);
   });

   

  }

  public void Initialize(Context ctx)
  {
   Context = ctx;
   mod = ctx.analyzer.targetCtx.Module_mono;

   ProtectionContext txt = txts[mod] = new ProtectionContext();

   txt.mcd = mod.Import(typeof(MulticastDelegate));
   txt.v = mod.TypeSystem.Void;
   txt.obj = mod.TypeSystem.Object;
   txt.ptr = mod.TypeSystem.IntPtr;

   txt.txts = new List<DelegateContext>();
   txt.delegates = new Dictionary<string, TypeDefinition>();
   txt.fields = new Dictionary<string, FieldDefinition>();
   txt.bridges = new Dictionary<string, MethodDefinition>();

  } //1

  public void FirstPhase(Context ctx)
  {
   ProtectionContext txt = txts[mod];

   TypeDefinition modType = mod.GetType("<Module>");
   AssemblyDefinition i = AssemblyDefinition.ReadAssembly(typeof(Iid).Assembly.Location);
   i.MainModule.ReadSymbols();
   txt.proxy = i.MainModule.GetType("Proxies").Methods.FirstOrDefault(mtd => mtd.Name == "CtorProxy");
   txt.proxy = CecilHelper.Inject(mod, txt.proxy);
   modType.Methods.Add(txt.proxy);
   txt.proxy.IsAssembly = true;
   txt.proxy.Name = ctx.generator.GenerateNewNameChinese();

   Instruction placeholder = null;
   txt.key = (uint)new Random().Next();
   Mutator mutator = new Mutator();
   mutator.Mutate(new Random(), txt.proxy.Body);
   placeholder = mutator.Placeholder;

   #region NotUsed

   //if (txt.isNative)
   //{
   // txt.nativeDecr = new MethodDefinition(
   //     ctx.generator.GenerateNewName(),
   //     MethodAttributes.Abstract | MethodAttributes.CompilerControlled |
   //     MethodAttributes.ReuseSlot | MethodAttributes.Static,
   //     mod.TypeSystem.Int32);
   // txt.nativeDecr.ImplAttributes = MethodImplAttributes.Native;
   // txt.nativeDecr.Parameters.Add(new ParameterDefinition(mod.TypeSystem.Int32));
   // modType.Methods.Add(txt.nativeDecr);

   // do
   // {
   //  txt.exp = new ExpressionGenerator(new Random().Next()).Generate(6);
   //  txt.invExp = ExpressionInverser.InverseExpression(txt.exp);
   // } while ((txt.visitor = new x86Visitor(txt.invExp, null)).RegisterOverflowed);

   // Database.AddEntry("CtorProxy", "Exp", txt.exp);
   // Database.AddEntry("CtorProxy", "InvExp", txt.invExp);

   // CecilHelper.Replace(txt.proxy.Body, placeholder, new Instruction[]
   //                    {
   //                         Instruction.Create(OpCodes.Call, txt.nativeDecr)
   //                    });
   //}

   //else

   CecilHelper.Replace(txt.proxy.Body, placeholder, new Instruction[]
                      {
                            Instruction.Create(OpCodes.Ldc_I4, (int)txt.key),
                            Instruction.Create(OpCodes.Xor)
                      });

   #endregion
  } //2

  public void SecondPhase(Context ctx)
  {
   ProtectionContext txt = txts[mod];

   bool onlyExternal = true;

   foreach(var mtd  in  ctx.analyzer.targetCtx.targets_mono)
   {
    if (mtd.DeclaringType == mod.GetType("<Module>")) /*continue;*/
    {
     MethodBody bdy = mtd.Body;
     foreach (Instruction inst in bdy.Instructions)
     {
      if (inst.OpCode.Code == Code.Newobj &&
          (!onlyExternal || !(inst.Operand is MethodDefinition)) &&
          !((inst.Operand as MethodReference).DeclaringType is GenericInstanceType) &&
          !((inst.Operand as MethodReference).DeclaringType is ArrayType) &&  //avoid array
          !(inst.Operand is GenericInstanceMethod))
      {
       CreateDelegate(mtd.Body, inst, inst.Operand as MethodReference, mod);
      }
     }
    }
    
   }

   int total = txts.Count;
   int interval = 1;
   if (total > 1000)
    interval = (int)total / 100;
   for (int i = 0; i < txt.txts.Count; i++)
   {
    CreateFieldBridge(mod, txt.txts[i]);
   }

  } //3

  public void ThirdPhase()
  {
   ProtectionContext _txt = txts[mod];

   int total = _txt.txts.Count;
   int interval = 1;
   if (total > 1000)
    interval = (int)total / 100;
   for (int i = 0; i < _txt.txts.Count; i++)
   {
    DelegateContext txt = _txt.txts[i];
    txt.fld.Name = GetId(txt.mtdRef.Module, txt.mtdRef);

    if (!(txt.fld as IAnnotationProvider).Annotations.Contains("CtorProxyCtored"))
    {
     ILProcessor psr = txt.dele.GetStaticConstructor().Body.GetILProcessor();
     psr.Emit(OpCodes.Ldtoken, txt.fld);
     psr.Emit(OpCodes.Call, _txt.proxy);
     (txt.fld as IAnnotationProvider).Annotations["CtorProxyCtored"] = true;
    }
   }

   total = _txt.delegates.Count;
   interval = 1;
   if (total > 1000)
    interval = (int)total / 100;
   IEnumerator<TypeDefinition> etor = _txt.delegates.Values.GetEnumerator();
   etor.MoveNext();
   for (int i = 0; i < _txt.delegates.Count; i++)
   {
    etor.Current.GetStaticConstructor().Body.GetILProcessor().Emit(OpCodes.Ret);
    etor.MoveNext();
   }
  }

  public void FirstFinalPhase(MetadataProcessor.MetadataAccessor accessor, Context ctx)
  {
   ProtectionContext _txt = txts[accessor.Module];
   for (int i = 0; i < _txt.txts.Count; i++)
   {
    int j = new Random().Next(0, _txt.txts.Count);
    var tmp = _txt.txts[i];
    _txt.txts[i] = _txt.txts[j];
    _txt.txts[j] = tmp;
   }

   TypeDefinition typeDef = new TypeDefinition("", "", 0);

   foreach (DelegateContext txt in _txt.txts)
   {
    txt.token = accessor.LookupToken(txt.mtdRef);
    if (txt.fld.Name[0] != '\0') continue;
    txt.fld.Name = " \n" + ctx.generator.GenerateNewNameChinese();

    //Hack into cecil to generate diff sig for diff field -_-
    int pos = txt.fld.DeclaringType.Fields.IndexOf(txt.fld) + 1;
    while (typeDef.GenericParameters.Count < pos)
     typeDef.GenericParameters.Add(new GenericParameter(typeDef));

    txt.fld.FieldType = new GenericInstanceType(txt.fld.FieldType)
    {
     GenericArguments =
                        {
                            accessor.Module.TypeSystem.Object,
                            accessor.Module.TypeSystem.Object,
                            accessor.Module.TypeSystem.Object,
                            accessor.Module.TypeSystem.Object,
                            accessor.Module.TypeSystem.Object,
                            typeDef.GenericParameters[pos - 1]
                        }
    };
   }
  }

  public void SecondFinalPhase(MetadataProcessor.MetadataAccessor accessor, Context ctx)
  {
   ProtectionContext txt = txts[accessor.Module];

   var fieldTbl = accessor.TableHeap.GetTable<FieldTable>(Table.Field);
   foreach (var i in txt.txts)
   {

    var fieldRow = fieldTbl[(int)i.fld.MetadataToken.RID - 1];

    TypeReference typeRef = i.fld.FieldType;
    accessor.BlobHeap.Position = (int)fieldRow.Col3;
    int len = (int)accessor.BlobHeap.ReadCompressedUInt32();
    int s = accessor.BlobHeap.Position;
    accessor.BlobHeap.WriteByte(0x6);
    accessor.BlobHeap.WriteByte((byte)(typeRef.IsValueType ? ElementType.ValueType : ElementType.Class));
    accessor.BlobHeap.WriteCompressedUInt32(CodedIndex.TypeDefOrRef.CompressMetadataToken(accessor.LookupToken(typeRef.GetElementType())));
    int l = len - (accessor.BlobHeap.Position - s);
    for (int z = 0; z < l; z++)
     accessor.BlobHeap.WriteByte(0);

    accessor.BlobHeap.Position = s + len - 8;
    byte[] b;
    if (txt.isNative)
     b = BitConverter.GetBytes(ExpressionEvaluator.Evaluate(txt.exp, (int)i.token.RID));
    else
     b = BitConverter.GetBytes(i.token.RID ^ txt.key);
    accessor.BlobHeap.WriteByte((byte)(((byte)new Random().Next() & 0x3f) | 0xc0));
    accessor.BlobHeap.WriteByte((byte)((uint)i.token.TokenType >> 24));
    accessor.BlobHeap.WriteByte(b[0]);
    accessor.BlobHeap.WriteByte(b[1]);
    accessor.BlobHeap.WriteByte((byte)(((byte)new Random().Next() & 0x3f) | 0xc0));
    accessor.BlobHeap.WriteByte(b[2]);
    accessor.BlobHeap.WriteByte(b[3]);
    accessor.BlobHeap.WriteByte(0);

    System.Diagnostics.Debug.Assert(accessor.BlobHeap.Position - (int)fieldRow.Col3 == len + 1);

    fieldTbl[(int)i.fld.MetadataToken.RID - 1] = fieldRow;
   }
  }

  /* --------- HELPERS ----------- */
  private void CreateDelegate(MethodBody Bdy, Instruction Inst, MethodReference MtdRef, ModuleDefinition Mod)
  {
   //Limitation
   TypeDefinition tmp = MtdRef.DeclaringType.Resolve();
   if (tmp != null && tmp.BaseType != null &&
       (tmp.BaseType.FullName == "System.MulticastDelegate" ||
       tmp.BaseType.FullName == "System.Delegate"))
    return;

   ProtectionContext _txt = txts[mod];

   DelegateContext txt = new DelegateContext();
   txt.inst = Inst;
   txt.bdy = Bdy;
   txt.mtdRef = MtdRef;
   string sign = GetSignatureO(MtdRef);
   if (!_txt.delegates.TryGetValue(sign, out txt.dele))
   {
    txt.dele = new TypeDefinition("", sign, TypeAttributes.NotPublic | TypeAttributes.Sealed, _txt.mcd);
    Mod.Types.Add(txt.dele);

    MethodDefinition cctor = new MethodDefinition(".cctor", MethodAttributes.Private | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName | MethodAttributes.Static, _txt.v);
    cctor.Body = new MethodBody(cctor);
    txt.dele.Methods.Add(cctor);

    MethodDefinition ctor = new MethodDefinition(".ctor", 0, _txt.v);
    ctor.IsRuntime = true;
    ctor.HasThis = true;
    ctor.IsHideBySig = true;
    ctor.IsRuntimeSpecialName = true;
    ctor.IsSpecialName = true;
    ctor.IsPublic = true;
    ctor.Parameters.Add(new ParameterDefinition(_txt.obj));
    ctor.Parameters.Add(new ParameterDefinition(_txt.ptr));
    txt.dele.Methods.Add(ctor);

    MethodDefinition invoke = new MethodDefinition("Invoke", 0, mod.Import(MtdRef.DeclaringType));
    TypeReference retType = invoke.ReturnType.GetElementType();
    retType.IsValueType = (retType.Resolve() ?? retType).IsValueType;

    invoke.IsRuntime = true;
    invoke.HasThis = true;
    invoke.IsHideBySig = true;
    invoke.IsVirtual = true;
    invoke.IsPublic = true;

    for (int i = 0; i < MtdRef.Parameters.Count; i++)
    {
     invoke.Parameters.Add(new ParameterDefinition(GetNameO(MtdRef.Parameters[i]), MtdRef.Parameters[i].Attributes, MtdRef.Parameters[i].ParameterType));
    }
    txt.dele.Methods.Add(invoke);
    _txt.delegates.Add(sign, txt.dele);

   }
   _txt.txts.Add(txt);
  }
  private void CreateFieldBridge(ModuleDefinition Mod, DelegateContext txt)
  {
   ProtectionContext _txt = txts[mod];

   ////////////////Field
   string fldId = GetId(Mod, txt.mtdRef);
   if (!_txt.fields.TryGetValue(fldId, out txt.fld))
   {
    txt.fld = new FieldDefinition(fldId, FieldAttributes.Static | FieldAttributes.Assembly, txt.dele);
    txt.dele.Fields.Add(txt.fld);
    _txt.fields.Add(fldId, txt.fld);
   }
   ////////////////Bridge
   string bridgeId = GetNameO(txt.mtdRef);
   MethodDefinition bdge;
   if (!_txt.bridges.TryGetValue(bridgeId, out bdge))
   {
    bdge = new MethodDefinition(bridgeId, MethodAttributes.Static | MethodAttributes.Assembly,
        mod.Import(txt.dele.Methods.Single(_ => _.Name == "Invoke").ReturnType));
    for (int i = 0; i < txt.mtdRef.Parameters.Count; i++)
    {
     bdge.Parameters.Add(new ParameterDefinition(GetNameO(txt.mtdRef.Parameters[i]), txt.mtdRef.Parameters[i].Attributes, txt.mtdRef.Parameters[i].ParameterType));
    }
    {
     ILProcessor psr = bdge.Body.GetILProcessor();
     psr.Emit(OpCodes.Ldsfld, txt.fld);
     for (int i = 0; i < bdge.Parameters.Count; i++)
     {
      psr.Emit(OpCodes.Ldarg, bdge.Parameters[i]);
     }
     psr.Emit(OpCodes.Call, txt.dele.Methods.FirstOrDefault(mtd => mtd.Name == "Invoke"));
     psr.Emit(OpCodes.Ret);
    }
    txt.dele.Methods.Add(bdge);
    _txt.bridges.Add(bridgeId, bdge);
   }

   ////////////////Replace
   txt.inst.OpCode = OpCodes.Call;
   txt.inst.Operand = bdge;
  }

  string GetNameO(MethodReference mbr)
  {
   return Context.generator.GenerateNewNameChinese();
  }
  string GetNameO(ParameterDefinition arg)
  {
   return Context.generator.GenerateNewNameChinese();
  }
  string GetSignatureO(MethodReference mbr)
  {
   return Context.generator.GenerateNewNameChinese();
  }
  static string GetSignature(MethodReference mbr)
  {
   StringBuilder sig = new StringBuilder();
   sig.Append(mbr.ReturnType.FullName);
   if (mbr.Resolve() != null && mbr.Resolve().IsVirtual)
    sig.Append(" virtual");
   if (mbr.HasThis)
    sig.Append(" " + mbr.DeclaringType.ToString());
   if (mbr.Name == ".cctor" || mbr.Name == ".ctor")
    sig.Append(mbr.Name);
   sig.Append(" (");
   if (mbr.HasParameters)
   {
    for (int i = 0; i < mbr.Parameters.Count; i++)
    {
     if (i > 0)
     {
      sig.Append(",");
     }
     sig.Append(mbr.Parameters[i].ParameterType.FullName);
    }
   }
   sig.Append(")");
   return sig.ToString();
  }

  static string GetId(ModuleDefinition mod, MethodReference mtd)
  {
   char asmRef = (char)(mod.AssemblyReferences.IndexOf(mtd.DeclaringType.Scope as AssemblyNameReference) + 2);
   return "\0" + asmRef + mtd.ToString();
  }

  /* --------- HELPERS ----------- */

 }
}
