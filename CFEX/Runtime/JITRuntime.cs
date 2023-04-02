using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using static Runtime.JITRuntime.ClrJit.ICorJitCompiler;

namespace Runtime
{
 internal static unsafe class JITRuntime
 {

  private static ClrJit.ICorJitCompiler.CompileMethodDelegate OriginalCompileMethod;
  private static ClrJit.ICorJitCompiler.CompileMethodDelegate CustomCompileMethod;

  static JITRuntime()
  {
   foreach (var method in typeof(JITRuntime).GetMethods(
       BindingFlags.Public
       | BindingFlags.Static
       | BindingFlags.NonPublic))
   {
    RuntimeHelpers.PrepareMethod(method.MethodHandle);
   }

   CustomCompileMethod = new ClrJit.ICorJitCompiler.CompileMethodDelegate(CompileMethod);
   RuntimeHelpers.PrepareDelegate(CustomCompileMethod);
  }

  public static void Hook()
  {
   var jitCompiler = *ClrJit.GetJit();
   OriginalCompileMethod = jitCompiler.CompileMethod;
   jitCompiler.CompileMethod = CustomCompileMethod;
  }

  public static void Unhook()
  {
   var jitCompiler = *ClrJit.GetJit();
   jitCompiler.CompileMethod = OriginalCompileMethod;
  }

  private static RuntimeMethodHandle IntPtrToMethodHandle(IntPtr intPtr)
  {
   var handle = new RuntimeMethodHandle();
   handle.GetType().GetFields(BindingFlags.NonPublic).First().SetValue(handle, intPtr);
   return handle;
  }

  public static ClrJit.CorJitResult CompileMethod(
      ClrJit.ICorJitCompiler* thisPtr,
      void* jitInfo,
      ClrJit.CORINFO_METHOD_INFO* info,
      ClrJit.CorJitFlag flags,
      byte** nativeEntry,
      ulong* nativeSizeOfCode)
  {
   Decryptor(info);
   var result = OriginalCompileMethod(thisPtr, jitInfo, info, flags, nativeEntry, nativeSizeOfCode);
   return result;
  }
  static byte[] key = Convert.FromBase64String("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==");
  //[MethodImpl(MethodImplOptions.ForwardRef)]
  static void Decryptor(ClrJit.CORINFO_METHOD_INFO* info)
  {
   uint s = info->ILCodeSize; //IL size

   int ok = 0; //If IL is encrypted code

   byte[] c = new byte[s]; //Loaded IL code

   byte first = 0x00;
   for (int i = 0; i < s; i++)
   {
    byte b = info->ILCode[i];
    if ((byte)(b ^ key[i % key.Length]) == first)
    {
     ok++; //Is NOP?
    }
    else
    {
     ok = 0;
    }


    if (ok == 5) //5x NOP mean code is encrypted
    {
     for (int j = 0; j < s; j++)
     {
      byte b0 = info->ILCode[j];
      c[j] = (byte)(b0 ^ key[j % key.Length]); //Decrypt IL
     }

     fixed (byte* il = c)
     {
      info->ILCode = il; //Put decrypted code to pointer (replace)
      return;
     }
    }
   }
  }

  [DllImport("kernel32.dll", EntryPoint = "VirtualProtect")]
  internal unsafe static extern bool VirtualProtect(byte* a, int b, uint c, ref uint d);
  public static unsafe void AntiDump()
  {
   byte* ptr = (byte*)((void*)Marshal.GetHINSTANCE(typeof(AntiDump).Module));
   byte* ptr6 = ptr + 60;
   ptr6 = ptr + *(uint*)ptr6;
   ptr6 += 6;
   ushort num15 = *(ushort*)ptr6;
   ptr6 += 14;
   ushort num16 = *(ushort*)ptr6;
   ptr6 = ptr6 + 4 + num16;
   UIntPtr uintPtr = (UIntPtr)11;
   uint num17 = 0;
   bool flag3 = VirtualProtect(ptr6 - 16, 8, 64u, ref num17);
   *(int*)(ptr6 - 12) = 0;
   byte* ptr7 = ptr + *(uint*)(ptr6 - 16);
   *(int*)(ptr6 - 16) = 0;
   bool flag4 = VirtualProtect(ptr7, 72, 64u, ref num17);
   byte* ptr8 = ptr + *(uint*)(ptr7 + 8);
   *(int*)ptr7 = 0;
   *(int*)(ptr7 + 4) = 0;
   *(int*)(ptr7 + (int)2 * 4) = 0;
   *(int*)(ptr7 + (int)3 * 4) = 0;
   bool flag5 = VirtualProtect(ptr8, 4, 64u, ref num17);
   *(int*)ptr8 = 0;
   for (int j = 0; j < (int)num15; j++)
   {
    bool flag6 = VirtualProtect(ptr6, 8, 64u, ref num17);
    Marshal.Copy(new byte[8], 0, (IntPtr)((void*)ptr6), 8);
    ptr6 += 40;
   }
  }

  public static unsafe partial class ClrJit
  {
   [Flags]
   public enum CorJitFlag : uint
   {
    SPEED_OPT = 0x00000001,
    SIZE_OPT = 0x00000002,
    DEBUG_CODE = 0x00000004,
    DEBUG_EnC = 0x00000008,
    DEBUG_INFO = 0x00000010,
    MIN_OPT = 0x00000020,
    GCPOLL_CALLS = 0x00000040,
    MCJIT_BACKGROUND = 0x00000080,

    UNUSED1 = 0x00000100,

    UNUSED2 = 0x00000200,
    UNUSED3 = 0x00000400,
    UNUSED4 = 0x00000800,
    UNUSED5 = 0x00001000,
    UNUSED6 = 0x00002000,

    MAKEFINALCODE = 0x00008000,
    READYTORUN = 0x00010000,

    PROF_ENTERLEAVE = 0x00020000,
    PROF_REJIT_NOPS = 0x00040000,
    PROF_NO_PINVOKE_INLINE
                        = 0x00080000,
    SKIP_VERIFICATION = 0x00100000,
    PREJIT = 0x00200000,
    RELOC = 0x00400000,
    IMPORT_ONLY = 0x00800000,
    IL_STUB = 0x01000000,
    PROCSPLIT = 0x02000000,
    BBINSTR = 0x04000000,
    BBOPT = 0x08000000,
    FRAMED = 0x10000000,
    ALIGN_LOOPS = 0x20000000,
    PUBLISH_SECRET_PARAM = 0x40000000,
    GCPOLL_INLINE = 0x80000000,

   };

   public enum CorJitResult : uint
   {
    OK = 0,
    BADCODE = 1,
    OUTOFMEM = 2,
    INTERNALERROR = 3,
    SKIPPED = 4,
    RECOVERABLEERROR = 5,
   };

   [Flags]
   public enum CorInfoOptions
   {
    OPT_INIT_LOCALS = 0x00000010,
    GENERICS_CTXT_FROM_THIS = 0x00000020,
    GENERICS_CTXT_FROM_METHODDESC = 0x00000040,
    GENERICS_CTXT_FROM_METHODTABLE = 0x00000080,
    GENERICS_CTXT_MASK = (GENERICS_CTXT_FROM_THIS |
                          GENERICS_CTXT_FROM_METHODDESC |
                          GENERICS_CTXT_FROM_METHODTABLE),
    GENERICS_CTXT_KEEP_ALIVE = 0x00000100,
   }

   [Flags]
   public enum CorInfoRegionKind
   {
    NONE,
    HOT,
    COLD,
    JIT,
   }

   [Flags]
   public enum CorInfoCallConv
   {
    DEFAULT = 0x0,
    C = 0x1,
    STDCALL = 0x2,
    THISCALL = 0x3,
    FASTCALL = 0x4,
    VARARG = 0x5,
    FIELD = 0x6,
    LOCAL_SIG = 0x7,
    PROPERTY = 0x8,
    NATIVEVARARG = 0xb,

    MASK = 0x0f,
    GENERIC = 0x10,
    HASTHIS = 0x20,
    EXPLICITTHIS = 0x40,
    PARAMTYPE = 0x80,
   };

   public enum CorInfoType
   {
    UNDEF = 0x0,
    VOID = 0x1,
    BOOL = 0x2,
    CHAR = 0x3,
    BYTE = 0x4,
    UBYTE = 0x5,
    SHORT = 0x6,
    USHORT = 0x7,
    INT = 0x8,
    UINT = 0x9,
    LONG = 0xa,
    ULONG = 0xb,
    NATIVEINT = 0xc,
    NATIVEUINT = 0xd,
    FLOAT = 0xe,
    DOUBLE = 0xf,
    STRING = 0x10,
    PTR = 0x11,
    BYREF = 0x12,
    VALUECLASS = 0x13,
    CLASS = 0x14,
    REFANY = 0x15,
    VAR = 0x16,
    COUNT,
   }

   [StructLayout(LayoutKind.Sequential, Pack = 1)]
   public struct CORINFO_METHOD_INFO
   {
    public IntPtr methodHandle;
    public IntPtr moduleHandle;
    public byte* ILCode;
    public uint ILCodeSize;
    public ushort maxStack;
    public ushort EHcount;
    public CorInfoOptions options;
    public CorInfoRegionKind regionKind;

    // TODO: add support for 32-bit and 64-bit apps.
   }

   [StructLayout(LayoutKind.Sequential, Pack = 1)]
   public struct CORINFO_SIG_INFO
   {
    public CorInfoCallConv callConv;
    public IntPtr retTypeClass;
    public IntPtr retTypeSigClass;
    public CorInfoType retType;
    public uint flags;
    public uint numArgs;
    public CORINFO_SIG_INST sigInst;
    public IntPtr args;
    public IntPtr pSig;
    public uint cbSig;
    public IntPtr scope;
    public uint token;
   };

   [StructLayout(LayoutKind.Sequential, Pack = 1)]
   public struct CORINFO_SIG_INST
   {
    uint classInstCount;
    IntPtr* classInst;
    uint methInstCount;
    IntPtr* methInst;
   };

  }

  public static unsafe partial class ClrJit
  {
   [DllImport("clrjit.dll", EntryPoint = "getJit", CallingConvention = CallingConvention.StdCall)]
   private static extern ICorJitCompiler* __getJit();

   public static ICorJitCompiler* GetJit()
   {
    ICorJitCompiler* jit = __getJit();
    if (jit == null)
     throw new Win32Exception();
    return jit;
   }

   [StructLayout(LayoutKind.Sequential, Pack = 1)]
   public struct ICorJitCompiler
   {
    private FunctionPointer* _vtable;

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate CorJitResult CompileMethodDelegate(
        ICorJitCompiler* thisPtr,
        void* jitInfo,
        CORINFO_METHOD_INFO* info,
        CorJitFlag flags,
        byte** nativeEntry,
        ulong* nativeSizeOfCode);

    public CompileMethodDelegate CompileMethod
    {
     get
     {
      return _vtable[0].GetDelegate();
     }
     set
     {
      Kernel32.Protection oldProtection;
      Kernel32.VirtualProtect(
          (IntPtr)_vtable,
          (uint)sizeof(FunctionPointer),
          Kernel32.Protection.PAGE_EXECUTE_READWRITE,
          out oldProtection);

      _vtable[0] = new FunctionPointer(value);

      Kernel32.VirtualProtect(
          (IntPtr)_vtable,
          (uint)sizeof(FunctionPointer),
          oldProtection,
          out oldProtection);
     }
    }
   }

  }

  public static class Kernel32
  {
   [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualProtect")]
   private static extern bool __VirtualProtect(
       IntPtr lpAddress,
       uint dwSize,
       Protection flNewProtect,
       out Protection lpflOldProtect);

   public static void VirtualProtect(
       IntPtr lpAddress,
       uint dwSize,
       Protection flNewProtect,
       out Protection lpflOldProtect)
   {
    if (!__VirtualProtect(lpAddress, dwSize, flNewProtect, out lpflOldProtect))
     throw new Win32Exception();
   }

   public enum Protection : uint
   {
    PAGE_NOACCESS = 0x01,
    PAGE_READONLY = 0x02,
    PAGE_READWRITE = 0x04,
    PAGE_WRITECOPY = 0x08,
    PAGE_EXECUTE = 0x10,
    PAGE_EXECUTE_READ = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40,
    PAGE_EXECUTE_WRITECOPY = 0x80,
    PAGE_GUARD = 0x100,
    PAGE_NOCACHE = 0x200,
    PAGE_WRITECOMBINE = 0x400
   }
  }

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public unsafe struct FunctionPointer
  {
   private IntPtr _ptr;

   public FunctionPointer(IntPtr ptr)
   {
    _ptr = ptr;
   }

   public FunctionPointer(Delegate @delegate)
   {
    _ptr = Marshal.GetFunctionPointerForDelegate(@delegate);
   }

   public CompileMethodDelegate GetDelegate()
   {
    //return Marshal.GetDelegateForFunctionPointer<TDelegate>(_ptr);
    return (CompileMethodDelegate)Marshal.GetDelegateForFunctionPointer(_ptr, typeof(CompileMethodDelegate));

   }
  }

 }
}
