using System.Collections.Generic;
using dnlib.DotNet;
using System;
using System.Text;
using System.Security.Cryptography;
using System.Linq;

namespace Eddy_Protector.Virtualization.RT.Mutation
{
	public class Renamer
	{
		private readonly Dictionary<string, string> nameMap = new Dictionary<string, string>();
		private int next;

		public Renamer(int seed)
		{
			next = seed;
		}

		private string ToString(int id)
		{
			return id.ToString("x");
		}

  //private string NewName(string name)
  //{
  //	string newName;
  //	if (!nameMap.TryGetValue(name, out newName))
  //	{
  //		nameMap[name] = newName = ToString(next);
  //		next = next * 0x19660D + 0x3C6EF35F;
  //	}
  //	return newName;
  //}


  //private string NewName(string name)
  //{

  //	byte[] hash = MD5.Create().ComputeHash(Encoding.Unicode.GetBytes(name));
  //	string result = string.Empty;

  //	for (int i = 0; i < hash.Length; i++)
  //	{
  //		result += hash[i].ToString("x2").ToUpper();
  //	}

  //	return "Eddy^CZ_" + result;

  //}

  static readonly char[] unicodeCharset = new char[] { }
.Concat(Enumerable.Range(0x200b, 5).Select(ord => (char)ord))
.Concat(Enumerable.Range(0x2029, 6).Select(ord => (char)ord))
.Concat(Enumerable.Range(0x206a, 6).Select(ord => (char)ord))
.Except(new[] { '\u2029' })
.ToArray();

  public string NewName(string f)
  {
   //int lengt = 2;
   byte[] buffer = SHA1.Create().ComputeHash(Encoding.Unicode.GetBytes(f)).Take(4).ToArray();
   //new RNGCryptoServiceProvider().GetBytes(buffer);
   string str_result = EncodeString(buffer, unicodeCharset);
   //int counter = int.MaxValue;
   //foreach (byte b in buffer)
   //{
   // counter--;
   // str_result += (char)((int)b ^ (int)counter);
   //}
   return str_result;
  }

  private string EncodeString(byte[] buff, char[] charset)
  {
   int current = buff[0];
   var ret = new StringBuilder();
   for (int i = 1; i < buff.Length; i++)
   {
    current = (current << 8) + buff[i];
    while (current >= charset.Length)
    {
     ret.Append(charset[current % charset.Length]);
     current /= charset.Length;
    }
   }
   if (current != 0)
    ret.Append(charset[current % charset.Length]);
   return ret.ToString();
  }

  //public string NewName(string f)
  //{
  // byte[] b = SHA512.Create().ComputeHash(Encoding.BigEndianUnicode.GetBytes(f));
  // new RNGCryptoServiceProvider().GetBytes(b);
  // return Encoding.BigEndianUnicode.GetString(b);
  //}

  public void Process(ModuleDef module)
		{
			foreach (var type in module.GetTypes())
			{
				//if (!type.IsPublic)
				//{
					type.Namespace = "";
					type.Name = NewName(type.FullName);
				//}
				foreach (var genParam in type.GenericParameters)
					genParam.Name = "";

				var isDelegate = type.BaseType != null &&
																					(type.BaseType.FullName == "System.Delegate" ||
																						type.BaseType.FullName == "System.MulticastDelegate");

				foreach (var method in type.Methods)
				{
					if (method.HasBody)
						foreach (var instr in method.Body.Instructions)
						{
							var memberRef = instr.Operand as MemberRef;
							if (memberRef != null)
							{
								var typeDef = memberRef.DeclaringType.ResolveTypeDef();

								if (memberRef.IsMethodRef && typeDef != null)
								{
									var target = typeDef.ResolveMethod(memberRef);
									if (target != null && target.IsRuntimeSpecialName)
										typeDef = null;
								}

								if (typeDef != null && typeDef.Module == module)
									memberRef.Name = NewName(memberRef.Name);
							}
						}

					foreach (var arg in method.Parameters)
						arg.Name = "";
					if (method.IsRuntimeSpecialName || isDelegate /*|| type.IsPublic*/)
						continue;
					method.Name = NewName(method.Name);
					method.CustomAttributes.Clear();
				}
				for (var i = 0; i < type.Fields.Count; i++)
				{
					var field = type.Fields[i];
					if (field.IsLiteral)
					{
						type.Fields.RemoveAt(i--);
						continue;
					}
					if (field.IsRuntimeSpecialName)
						continue;
					field.Name = NewName(field.Name);
				}
				type.Properties.Clear();
				type.Events.Clear();
				type.CustomAttributes.Clear();
			}
		}
	}
}