using System;

namespace Eddy_Protector_Runtime
{
 static partial class AntiDebugAntinet
 {
  static void Initialize()
  {
   if (!InitializeAntiDebugger())
    Environment.FailFast(null);
   InitializeAntiProfiler();
   if (IsProfilerAttached)
   {
    Environment.FailFast(null);
    PreventActiveProfilerFromReceivingProfilingMessages();
   }
  }
 }
}