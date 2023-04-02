using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System.Security.Cryptography;
using System.Text;

namespace Eddy_Protector.Virtualization.RT.Mutation
{
	internal class RuntimeMutator : IModuleWriterListener
	{
		internal RTConstants constants;
		private RuntimeHelpers helpers;
		private readonly MethodPatcher methodPatcher;
		private readonly VMRuntime rt;
		private MetaData rtMD;
		private ModuleWriterBase rtWriter;


  public RuntimeMutator(ModuleDef module, VMRuntime rt)
		{
			RTModule = module;
			this.rt = rt;
   methodPatcher = new MethodPatcher(module);

			constants = new RTConstants();
			helpers = new RuntimeHelpers(constants, rt, module);
			constants.InjectConstants(module, rt.Descriptor, helpers);
			helpers.AddHelpers();
		}

		public ModuleDef RTModule
		{
			get;
			set;
		}

		public byte[] RuntimeLib
		{
			get;
			private set;
		}

		public byte[] RuntimeSym
		{
			get;
			private set;
		}

		void IModuleWriterListener.OnWriterEvent(ModuleWriterBase writer, ModuleWriterEvent evt)
		{
			rtWriter = writer;
			rtMD = writer.MetaData;
			if (evt == ModuleWriterEvent.MDEndCreateTables)
			{
				MutateMetadata();
				var request = new RequestKoiEventArgs();
				RequestKoi(this, request);
				writer.TheOptions.MetaDataOptions.OtherHeaps.Add(request.Heap);

				rt.ResetData();
			}
		}

		public void InitHelpers()
		{
			helpers = new RuntimeHelpers(constants, rt, RTModule);
			helpers.AddHelpers();
		}

  //public string GenerateName()
  //{
  // byte[] b = new byte[32];
  // new RNGCryptoServiceProvider().GetBytes(b);
  // return Encoding.BigEndianUnicode.GetString(b);
  //}

  public string GenerateName()
  {
   int lengt = 2;
   byte[] buffer = new byte[lengt];
   new RNGCryptoServiceProvider().GetBytes(buffer);
   string str_result = String.Empty;
   foreach (byte b in buffer)
   {
    str_result += (char)b;
   }
   return str_result;
  }

  public void CommitRuntime(ModuleDef targetModule)
		{
			MutateRuntime();

			if (targetModule == null)
			{
				var stream = new MemoryStream();
				var pdbStream = new MemoryStream();

				var options = new ModuleWriterOptions(RTModule);

				RTModule.Write(stream, options);
				RuntimeLib = stream.ToArray();
				RuntimeSym = new byte[0];
			}
			else
			{
				var types = RTModule.Types.Where(t => !t.IsGlobalModuleType).ToList();
				RTModule.Types.Clear();
				foreach (var type in types) targetModule.Types.Add(type);
			}
		}

		public IModuleWriterListener CommitModule(ModuleDef module)
		{
			ImportReferences(module);
			return this;
		}

		public void ReplaceMethodStub(MethodDef method)
		{
			methodPatcher.PatchMethodStub(method, rt.Descriptor.Data.GetExportId(method));
		}

		public event EventHandler<RequestKoiEventArgs> RequestKoi;

		private void MutateRuntime()
		{
			var settings = rt.Descriptor.Settings;
			RuntimePatcher.Patch(RTModule, settings.ExportDbgInfo, settings.DoStackWalk);
			constants.InjectConstants(RTModule, rt.Descriptor, helpers);
			new Renamer(rt.Descriptor.Random.Next()).Process(RTModule);
   //RenameTwo(RTModule);
		}

  public void RenameTwo(ModuleDef rt)
  {

   foreach (TypeDef t in rt.GetTypes())
   {
    if (t.IsGlobalModuleType)
    {
     continue;
    }
    if (t.IsAbstract && t.IsSealed)
    {
     continue;
    }
    t.Namespace = GenerateName();
    t.Name = GenerateName();

    foreach (MethodDef m in t.Methods)
    {
     if (m.IsConstructor || m.DeclaringType.IsForwarder)
     {
      continue;
     }
     m.Name = GenerateName(); ;

     foreach (ParamDef p in m.ParamDefs)
     {
      p.Name = GenerateName();
     }

     if (m.HasBody && m.Body.HasVariables)
     {
      foreach (var vari in m.Body.Variables)
      {
       vari.Name = GenerateName();
      }
     }
    }

    foreach (FieldDef f in t.Fields)
    {
     if ((f.IsStatic || f.IsLiteral || f.DeclaringType.IsEnum))
     {
      continue;
     }
     f.Name = GenerateName();
    }

    foreach (EventDef e in t.Events)
    {
     e.Name = GenerateName();
    }
    foreach (PropertyDef p in t.Properties)
    {
     p.Name = GenerateName();
    }
   }
  }


  private void ImportReferences(ModuleDef module)
		{
			var refCopy = rt.Descriptor.Data.refMap.ToList();
			rt.Descriptor.Data.refMap.Clear();
			foreach (var mdRef in refCopy)
			{
				object item;
				if (mdRef.Key is ITypeDefOrRef)
					item = module.Import((ITypeDefOrRef)mdRef.Key);
				else if (mdRef.Key is MemberRef)
					item = module.Import((MemberRef)mdRef.Key);
				else if (mdRef.Key is MethodDef)
					item = module.Import((MethodDef)mdRef.Key);
				else if (mdRef.Key is MethodSpec)
					item = module.Import((MethodSpec)mdRef.Key);
				else if (mdRef.Key is FieldDef)
					item = module.Import((FieldDef)mdRef.Key);
				else
					item = mdRef.Key;
				rt.Descriptor.Data.refMap.Add((IMemberRef)item, mdRef.Value);
			}
			foreach (var sig in rt.Descriptor.Data.sigs)
			{
				var methodSig = sig.Signature;
				var funcSig = sig.FuncSig;

				if (methodSig.HasThis)
					funcSig.Flags |= rt.Descriptor.Runtime.RTFlags.INSTANCE;

				var paramTypes = new List<ITypeDefOrRef>();
				if (methodSig.HasThis && !methodSig.ExplicitThis)
				{
					IType thisType;
					if (sig.DeclaringType.IsValueType)
						thisType = module.Import(new ByRefSig(sig.DeclaringType.ToTypeSig()).ToTypeDefOrRef());
					else
						thisType = module.Import(sig.DeclaringType);
					paramTypes.Add((ITypeDefOrRef)thisType);
				}
				foreach (var param in methodSig.Params)
				{
					var paramType = (ITypeDefOrRef)module.Import(param.ToTypeDefOrRef());
					paramTypes.Add(paramType);
				}
				funcSig.ParamSigs = paramTypes.ToArray();

				var retType = (ITypeDefOrRef)module.Import(methodSig.RetType.ToTypeDefOrRef());
				funcSig.RetType = retType;
			}
		}

		private void MutateMetadata()
		{
			foreach (var mdRef in rt.Descriptor.Data.refMap)
				mdRef.Key.Rid = rtMD.GetToken(mdRef.Key).Rid;

			foreach (var sig in rt.Descriptor.Data.sigs)
			{
				var funcSig = sig.FuncSig;

				foreach (var paramType in funcSig.ParamSigs)
					paramType.Rid = rtMD.GetToken(paramType).Rid;

				funcSig.RetType.Rid = rtMD.GetToken(funcSig.RetType).Rid;
			}
		}
	}

	internal class RequestKoiEventArgs : EventArgs
	{
		public KoiHeap Heap
		{
			get;
			set;
		}
	}
}