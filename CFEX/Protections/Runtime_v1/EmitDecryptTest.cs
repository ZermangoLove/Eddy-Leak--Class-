using System;
using System.Collections.Generic;
using System.Text;

namespace Eddy_Protector_Runtime
{
 class EmitDecryptTest
 {

  public static void Emit()
  {
   uint[] w = new uint[] { 25, 36, 54, 85, 66, 99, 99 };
   uint[] k = new uint[] { 10, 66, 88, 77, 44, 11, 77 };
   Mutation.Crypt(w, k);
  }

 }
}
