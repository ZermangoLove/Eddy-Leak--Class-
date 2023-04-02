using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using dnlib.DotNet;

namespace Protector.Protections
{
 class ModuleRenamer
 {
  public ModuleDef RenameModule(ModuleDef module, ProtectorContext context)
  {
   module.Name = context.random_generator.GenerateString();
   module.Assembly.Name = context.random_generator.GenerateString();
   return module;
  }
 }
}
