using System;
using System.Reflection;
using System.Reflection.Emit;
using System.Diagnostics;
using System.Text;

namespace Protector.Runtime
{
	internal class RefProxyKey : Attribute
	{
		readonly int key;

		public RefProxyKey(int key)
		{
			this.key = Mutation.Placeholder(key);
		}

		public override int GetHashCode()
		{
			return key;
		}
	}

	internal static class RefProxyStrong
	{
		internal static void Initialize(RuntimeFieldHandle field, byte opKey)
		{
			if (Assembly.GetExecutingAssembly() == Assembly.GetCallingAssembly())
			{

				FieldInfo fieldInfo = FieldInfo.GetFieldFromHandle(field);

    //GetFromB encoded
    string fieldName = fieldInfo.Name;
    string decodedName = String.Empty;

    foreach(var ch in fieldName.ToCharArray())
    {
     int num = (int)ch ^ 1993;
     decodedName += (char)num;
    }

    string origFieldName = Encoding.Unicode.GetString(Convert.FromBase64String(decodedName));
    //

    byte[] sig = fieldInfo.Module.ResolveSignature(fieldInfo.MetadataToken);
				int len = sig.Length;
				int key = fieldInfo.GetOptionalCustomModifiers()[0].MetadataToken;

				key += (origFieldName[Mutation.KeyI0] ^ sig[--len]) << Mutation.KeyI4;
				key += (origFieldName[Mutation.KeyI1] ^ sig[--len]) << Mutation.KeyI5;
				key += (origFieldName[Mutation.KeyI2] ^ sig[--len]) << Mutation.KeyI6;
				len--;
				key += (origFieldName[Mutation.KeyI3] ^ sig[--len]) << Mutation.KeyI7;

				int token = Mutation.Placeholder(key);
				token *= fieldInfo.GetCustomAttributes(false)[0].GetHashCode();

				MethodBase method = fieldInfo.Module.ResolveMethod(token);
				Type delegateType = fieldInfo.FieldType;
				if (method.IsStatic)
					fieldInfo.SetValue(null, Delegate.CreateDelegate(delegateType, (MethodInfo)method));

				else
				{
					DynamicMethod dm = null;
					Type[] argTypes = null;

					foreach (MethodInfo invoke in fieldInfo.FieldType.GetMethods(BindingFlags.NonPublic | BindingFlags.Instance))
						if (invoke.DeclaringType == delegateType)
						{
							ParameterInfo[] paramTypes = invoke.GetParameters();
							argTypes = new Type[paramTypes.Length];
							for (int i = 0; i < argTypes.Length; i++)
								argTypes[i] = paramTypes[i].ParameterType;

							Type declType = method.DeclaringType;
							dm = new DynamicMethod("", invoke.ReturnType, argTypes, (declType.IsInterface || declType.IsArray) ? delegateType : declType, true);
							break;
						}

					DynamicILInfo info = dm.GetDynamicILInfo();
					info.SetLocalSignature(new byte[] { 0x7, 0x0 });
					var code = new byte[(2 + 5) * argTypes.Length + 6];
					int index = 0;
					var mParams = method.GetParameters();
					int mIndex = method.IsConstructor ? 0 : -1;
					for (int i = 0; i < argTypes.Length; i++)
					{
						code[index++] = 0x0e;
						code[index++] = (byte)i;

						var mType = mIndex == -1 ? method.DeclaringType : mParams[mIndex].ParameterType;
						if (mType.IsClass && !(mType.IsPointer || mType.IsByRef))
						{
							var cToken = info.GetTokenFor(mType.TypeHandle);
							code[index++] = 0x74;
							code[index++] = (byte)cToken;
							code[index++] = (byte)(cToken >> 8);
							code[index++] = (byte)(cToken >> 16);
							code[index++] = (byte)(cToken >> 24);
						}
						else
							index += 5;
						mIndex++;
					}


					code[index++] = (byte)((byte)origFieldName[Mutation.KeyI8] ^ opKey);
					int dmToken = info.GetTokenFor(method.MethodHandle);
					code[index++] = (byte)dmToken;
					code[index++] = (byte)(dmToken >> 8);
					code[index++] = (byte)(dmToken >> 16);
					code[index++] = (byte)(dmToken >> 24);
					code[index] = 0x2a;
					info.SetCode(code, argTypes.Length + 1);

					fieldInfo.SetValue(null, dm.CreateDelegate(delegateType));
				}
			}
			else
			{
				Process.GetCurrentProcess().Kill();
			}
		}
	}
}