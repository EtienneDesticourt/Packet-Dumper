using System;
using System.Runtime.InteropServices;
using Binarysharp.Assemblers.Fasm;
using System.IO;

namespace PacketDumper
{
        internal class PacketSnifferHook
        {
                private static HookType _hookDelegate;
                private static readonly IntPtr _hookAddress = (IntPtr)0x5900CB;
                private static string _filePath;

                public static void Install(string filePath)
                {
                        _filePath = filePath;
                        _hookDelegate = Hook;

                        IntPtr codeCave = Marshal.AllocHGlobal(128);

                        byte[] code = FasmNet.Assemble(new[]
                                {
                                        "use32",
                                        "org " + codeCave,
                                        "pushad",
                                        "push esi",     //add length of output buffer to args
                                        "sub eax, esi", //eax-esi is the location of the output buffer (originally eax then increased by esi bytes through the dec loop)
                                        "push eax",     //add buffer address to args
                                        "call " + Marshal.GetFunctionPointerForDelegate(_hookDelegate),
                                        "popad",
                                        "mov [ecx+4], edi", //Following lines replace the ones that were overwritten by the jump to the code cave
                                        "pop ebx",
                                        "mov [ecx], esi",
                                        "jmp " + (_hookAddress + 6) //Jump back into the decryption function past the overwritten lines
                                });
                        Marshal.Copy(code, 0, codeCave, code.Length);

                        Jump(_hookAddress, codeCave);
                }

                private static int Hook(IntPtr buf, int len)
                {
                        byte[] buffer = new byte[len];
                        Marshal.Copy(buf, buffer, 0, len);
                        File.AppendAllText(_filePath, DateTime.Now.ToString("h:mm:ss") + "\n" + BitConverter.ToString(buffer).Replace("-", " ") + "\n\n");
                        return 0;
                }

                private static void Jump(IntPtr from, IntPtr to)
                {
                        byte[] hook = FasmNet.Assemble(new[]
                                {
                                        "use32",
                                        "org " + from,
                                        "jmp " + to,
                                        "nop"
                                });

                        uint dwOldProtection;
                        Kernel32.VirtualProtect(from, 5, 0x40, out dwOldProtection);
                        Marshal.Copy(hook, 0, from, 5);
                        Kernel32.VirtualProtect(from, 5, dwOldProtection, out dwOldProtection);
                }

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                private delegate int HookType(IntPtr buf, int len);

        }
}