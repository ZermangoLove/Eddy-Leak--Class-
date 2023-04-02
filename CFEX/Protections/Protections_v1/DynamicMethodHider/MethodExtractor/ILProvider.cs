using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace ObfuscationCore.Extractor
{
 public interface IILProvider
 {
  Byte[] GetByteArray();
 }

 public class MethodBaseILProvider : IILProvider
 {
  MethodBase m_method;
  byte[] m_byteArray;

  public MethodBaseILProvider(MethodBase method)
  {
   m_method = method;
  }

  public byte[] GetByteArray()
  {
   if (m_byteArray == null)
   {
    MethodBody methodBody = m_method.GetMethodBody();
    m_byteArray = (methodBody == null) ? new Byte[0] : methodBody.GetILAsByteArray();
   }
   return m_byteArray;
  }
 }
}
