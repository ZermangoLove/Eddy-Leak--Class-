using dnlib.DotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;

namespace Protector.Protections.RefProxy
{
	abstract class RPMode
	{
		public abstract void ProcessCall(RPContext ctx, int instrIndex);
		public abstract void Finalize(RPContext ctx);

		static ITypeDefOrRef Import(RPContext ctx, TypeDef typeDef)
		{
			ITypeDefOrRef retTypeRef = new Importer(ctx.Module, ImporterOptions.TryToUseTypeDefs).Import(typeDef);		
			return retTypeRef;
		}

		protected static MethodSig CreateProxySignature(RPContext ctx, IMethod method, bool newObj)
		{
			ModuleDef module = ctx.Module;
			if (newObj)
			{
				TypeSig[] paramTypes = method.MethodSig.Params.Select(type => {
					if (ctx.TypeErasure && type.IsClassSig && method.MethodSig.HasThis)
						return module.CorLibTypes.Object;
					return type;
				}).ToArray();

				TypeSig retType;
				if (ctx.TypeErasure) // newobj will not be used with value types
					retType = module.CorLibTypes.Object;
				else
				{
					TypeDef declType = method.DeclaringType.ResolveTypeDef();

					retType = null;

					if (declType != null)
					{
						retType = Import(ctx, declType).ToTypeSig();
					}
					
				}
				return MethodSig.CreateStatic(retType, paramTypes);
			}
			else
			{
				IEnumerable<TypeSig> paramTypes = method.MethodSig.Params.Select(type => {
					if (ctx.TypeErasure && type.IsClassSig && method.MethodSig.HasThis)
						return module.CorLibTypes.Object;
					return type;
				});
				if (method.MethodSig.HasThis && !method.MethodSig.ExplicitThis)
				{
					TypeDef declType = method.DeclaringType.ResolveTypeDef();

					if (declType != null)
					{
						if (ctx.TypeErasure && !declType.IsValueType)
						{
							paramTypes = new[] { module.CorLibTypes.Object }.Concat(paramTypes);
						}

						else
						{
							paramTypes = new[] { Import(ctx, declType).ToTypeSig() }.Concat(paramTypes);
						}
					}
						
				}
				TypeSig retType = method.MethodSig.RetType;
				if (ctx.TypeErasure && retType.IsClassSig)
					retType = module.CorLibTypes.Object;
				return MethodSig.CreateStatic(retType, paramTypes.ToArray());
			}
		}

		protected static TypeDef GetDelegateType(RPContext ctx, MethodSig sig)
		{
			TypeDef ret;
			if (ctx.Delegates.TryGetValue(sig, out ret))
				return ret;

			ret = new TypeDefUser(ctx.ctx.random_generator.GenerateString(), ctx.Module.CorLibTypes.GetTypeRef("System", "MulticastDelegate"));
			ret.Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed;

			var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(ctx.Module.CorLibTypes.Void, ctx.Module.CorLibTypes.Object, ctx.Module.CorLibTypes.IntPtr));
			ctor.Attributes = MethodAttributes.Assembly | MethodAttributes.HideBySig | MethodAttributes.RTSpecialName | MethodAttributes.SpecialName;
			ctor.ImplAttributes = MethodImplAttributes.Runtime;
			ret.Methods.Add(ctor);

			var invoke = new MethodDefUser("Invoke", sig.Clone());
			invoke.MethodSig.HasThis = true;
			invoke.Attributes = MethodAttributes.Assembly | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot;
			invoke.ImplAttributes = MethodImplAttributes.Runtime;
			ret.Methods.Add(invoke);

			ctx.Module.Types.Add(ret);

			ctx.Delegates[sig] = ret;
			return ret;
		}
	}
}
