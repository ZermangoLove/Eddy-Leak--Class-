using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Eddy_Protector_Core.Core;
using dnlib.DotNet;

namespace Eddy_Protector_Protections.Protections.StringEncrypt
{
	public class ConstantContext
	{
		public Context context; 
		public Encryption Encrypt;
		public StringEncryptProtection protection;

		/* Keys */
		public List<string> UsedKeysLdstr = new List<string>();
		public List<string> UsedKeysLdci4 = new List<string>();

		/* Methods */
		public MethodDef LDSTRDecrypt_m;
		public MethodDef LDCI4Decrypt_m;

		public TypeDef GettypeDef(string TypeName, string AsmPath)
		{
			var tmpAsm = AssemblyDef.Load(AsmPath);
			var importmeType = tmpAsm.ManifestModule.Find(TypeName, false);
			return importmeType;
		}
		public MethodDef GetmethodDef(TypeDef tDef, string name)
		{
			var importmeType = tDef.FindMethod(name);
			return importmeType;
		}

		public MethodDef GetDecryptionMethod(string MethodName, string Literal)
		{
			TypeDef runtime = GettypeDef("Eddy_Protector_Runtime.Constant_Two", "Eddy_Protector_Runtime.dll");

			MethodDef decrypt = null;

			switch (Literal)
			{
				case "ldci4":
					decrypt = GetmethodDef(runtime, MethodName);
     break;
				case "ldstr":
					decrypt = GetmethodDef(runtime, MethodName);
					break;
			}



			decrypt.Name = context.generator.GenerateNewNameChinese();
			decrypt.DeclaringType = null;
			decrypt.Attributes = MethodAttributes.Static;

			//for (int a = 0; a < 1; a++)
			//{
			//	//context.runtime_mutation.DoMutation(decrypt, context);
			//	//context.runtime_controlflow2.DoControlFlow(decrypt, context);
			//}
			
			return decrypt;
		}
	}
}
