using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using dnlib.DotNet;
using Protector.Helpers;
using System.Security.Cryptography;
using System.IO;
using dnlib.DotNet.Emit;

namespace Protector.Protections.Antidump
{
 class AntiDumpEvassionProtection
 {
  public ModuleDef AddAntiDump(ModuleDef mod, ProtectorContext context)
  {

   TypeDefUser NewType = new TypeDefUser(context.random_generator.GenerateString(),
mod.CorLibTypes.Object.TypeDefOrRef);
   NewType.Attributes = TypeAttributes.NotPublic |
    TypeAttributes.AutoLayout |
        TypeAttributes.Class |
        TypeAttributes.AnsiClass;
   mod.Types.Add(NewType);

   /* Get runtime type */
   TypeDef rtType = DnLibHelper.GetRuntimeType("Protector.Runtime.ProcessSecure");

   IEnumerable<IDnlibDef> members = InjectHelper.Inject(rtType, NewType, mod);

   /* Get methods */
   MethodDef cctor = mod.GlobalType.FindOrCreateStaticConstructor();
   MethodDef init = (MethodDef)members.Single(method => method.Name == "IntializeEvasion");

   //GetLibraryPath

   MethodDef GetLibraryPath = (MethodDef)members.Single(method => method.Name == "GetLibraryPath");

   /* Create resource */
   int res_id = context.random_generator.RandomInt();
   string res_name = Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(res_id)));
   mod.Resources.Add(new EmbeddedResource(res_name, File.ReadAllBytes("ProcessSecure.dll"),
    ManifestResourceAttributes.Private));

   MutationHelper.InjectKeys(GetLibraryPath, new int[] { 0 }, new int[] {res_id });

   cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));

   return mod;
  }
 }
}
