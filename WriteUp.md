### Challenge: bypass IsDebuggerPresent in IsBeingDebugged.exe

#### source code

```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    if(IsDebuggerPresent()){
        printf("Yes !\n");
    }else{
        printf("No !\n");
    }
    getchar();
    return 0;
}
```

#### in windbg

```asm
0:000> x *!IsDebuggerPresent
00007ffd`6385b690 KERNELBASE!IsDebuggerPresent (IsDebuggerPresent)

0:000> bp KERNEL32!IsDebuggerPresentStub
	KERNEL32!IsDebuggerPresentStub: CFG
>> 00007ffd`653904f0 48ff25213e0600   jmp     qword ptr [KERNEL32!__imp_IsDebuggerPresent (7ffd653f4318)]
00007ffd`653904f7 cc               int     3
00007ffd`653904f8 cc               int     3

0:000> g
Breakpoint 1 hit
	KERNEL32!IsDebuggerPresentStub:
>> 00007ffd`653904f0 48ff25213e0600  jmp     qword ptr [KERNEL32!_imp_IsDebuggerPresent (00007ffd`653f4318)] ds:00007ffd`653f4318={KERNELBASE!IsDebuggerPresent (00007ffd`6385b690)}

0:000> k
 # Child-SP          RetAddr               Call Site
00 00000000`0066fdf8 00000000`0040157d     KERNELBASE!IsDebuggerPresent
01 00000000`0066fe00 00000000`004013f8     IsBeingDebugged+0x157d
02 00000000`0066fe30 00000000`0040151b     IsBeingDebugged!__tmainCRTStartup+0x248 [./mingw-w64-crt/crt/crtexe.c @ 336] 
03 00000000`0066ff00 00007ffd`65387374     IsBeingDebugged!mainCRTStartup+0x1b [./mingw-w64-crt/crt/crtexe.c @ 214] 
04 00000000`0066ff30 00007ffd`65fdcc91     KERNEL32!BaseThreadInitThunk+0x14
05 00000000`0066ff60 00000000`00000000     ntdll!RtlUserThreadStart+0x21 

0:000> t
KERNELBASE!IsDebuggerPresent:
00007ffd`6385b690 65488b042560000000 mov   rax,qword ptr gs:[60h] gs:00000000`00000060=????????????????

	KERNELBASE!IsDebuggerPresent: CFG
>> 00007ffd`6385b690 65488b042560000000 mov     rax, qword ptr gs:[60h]
00007ffd`6385b699 0fb64002           movzx   eax, byte ptr [rax+2]
00007ffd`6385b69d c3                 ret     
00007ffd`6385b69e cc                 int     3
00007ffd`6385b69f cc 

0:000> t
KERNELBASE!IsDebuggerPresent+0x9:
00007ffd`6385b699 0fb64002        movzx   eax,byte ptr [rax+2] ds:00000000`0023d002=01
0:000> t
KERNELBASE!IsDebuggerPresent+0xd:
00007ffd`6385b69d c3              ret

0:000> r rax=0
0:000> t
IsBeingDebugged+0x157d:
00000000`0040157d 85c0            test    eax,eax

IsBeingDebugged+0x157d
>> 0040157d 85c0                 test    eax, eax
0040157f 740e                 je      000000000040158F
00401581 488d0d782a0000       lea     rcx, [404000h]
00401588 e803160000           call    0000000000402B90
0040158d eb0c                 jmp     000000000040159B
0040158f 488d0d702a0000       lea     rcx, [404006h]
00401596 e8f5150000           call    0000000000402B90
0040159b e808160000           call    0000000000402BA8
004015a0 b800000000           mov     eax, 0
004015a5 4883c420             add     rsp, 20h
004015a9 5d                   pop     rbp
004015aa c3                   ret   

0:000> t
IsBeingDebugged+0x157f:
00000000`0040157f 740e            je      IsBeingDebugged+0x158f (00000000`0040158f) [br=1]
0:000> t
IsBeingDebugged+0x158f:
00000000`0040158f 488d0d702a0000  lea     rcx,[IsBeingDebugged+0x4006 (00000000`00404006)]
0:000> t
IsBeingDebugged+0x1596:
00000000`00401596 e8f5150000      call    IsBeingDebugged+0x2b90 (00000000`00402b90)
0:000> t
IsBeingDebugged+0x2b90:
00000000`00402b90 ff25f6570000    jmp     qword ptr [IsBeingDebugged+0x838c (00000000`0040838c)] ds:00000000`0040838c={msvcrt!puts (00007ffd`63ffe470)}
0:000> t
msvcrt!puts:
00007ffd`63ffe470 488bc4          mov     rax,rsp
...
```

### Challenge: LEAK KEYS STROKE in notepad-trace1.run

- HINT : MONITOR MESSAGES RECEIVED BY `USER32!GETMESSAGEW`, AND CHECK `WINTYPES!MSG.WPARAM`

#### meanings of message and wParam in MSG
```c
// https://learn.microsoft.com/zh-cn/windows/win32/api/winuser/nf-winuser-getmessagew
BOOL GetMessageW(
  [out]          LPMSG lpMsg,
  [in, optional] HWND  hWnd,
  [in]           UINT  wMsgFilterMin,
  [in]           UINT  wMsgFilterMax
);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg
typedef struct tagMSG {
  HWND   hwnd;
  UINT   message;
  WPARAM wParam;
  LPARAM lParam;
  DWORD  time;
  POINT  pt;
  DWORD  lPrivate;
} MSG, *PMSG, *NPMSG, *LPMSG;

// message
// https://learn.microsoft.com/en-us/windows/win32/inputdev/wm-keydown
// \Windows Kits\10\Include\10.x.x.x\um\WinUser.h
#define WM_KEYDOWN                      0x0100

// wParam
// https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
`A` 	0x41 	A key
`B` 	0x42 	B key
`C` 	0x43 	C key
```
#### in windbg
```asm
bp user32!GetMessageW "j (poi(rcx+8)==0x100) 'r @$t0=poi(rcx+10); .printf\"KEYDOWN:0x%x\", @$t0; .if( @$t0 >= 0x30 & @$t0 <= 0x5A ){ .printf\"(%c)\", @$t0 }; .echo; gc'; 'g'"
    
KEYDOWN:0x57(W)
KEYDOWN:0x49(I)
KEYDOWN:0x4e(N)
KEYDOWN:0x44(D)
KEYDOWN:0x42(B)
KEYDOWN:0x47(G)
KEYDOWN:0x20
KEYDOWN:0x49(I)
KEYDOWN:0x53(S)
KEYDOWN:0x20
KEYDOWN:0x41(A)
KEYDOWN:0x57(W)
KEYDOWN:0x45(E)
KEYDOWN:0x53(S)
KEYDOWN:0x4f(O)
KEYDOWN:0x4d(M)
KEYDOWN:0x45(E)
KEYDOWN:0x20
KEYDOWN:0x10
KEYDOWN:0x31(1)
```
### Challenge: FIND AND DUMP THE SHELLCODE ENCODED of Payroll
#### in ida
Based on the IDA disassembly results, the program utilizes the following functions: VirtualAlloc, memcpy, VirtualProtect, CreateThread, WaitForSingleObject, and VirtualFree. This sequence represents a typical C-based shellcode loading process.sub_401569 primarily calls VirtualAlloc to allocate memory for unk_403040, followed by XOR decryption via sub_4015E5 using a key starting at 0x13 that auto-increments in a 256-byte cycle. Thus, unk_403040 is the address of the SHELLCODE ENCODED. sub_401543 corresponds to CheckNtGlobalFlag in the xor-payload.py source code.
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  SIZE_T v3; // ebx
  HANDLE CurrentProcess; // eax
  DWORD flOldProtect; // [esp+0h] [ebp-28h] BYREF
  DWORD ThreadId[2]; // [esp+4h] [ebp-24h] BYREF
  HANDLE hHandle; // [esp+Ch] [ebp-1Ch]
  LPVOID lpAddress; // [esp+10h] [ebp-18h]
  HANDLE hObject; // [esp+14h] [ebp-14h]
  SIZE_T dwSize; // [esp+1Ch] [ebp-Ch]
  int *p_argc; // [esp+20h] [ebp-8h]

  p_argc = &argc;
  sub_4019D0();
  dwSize = 342;
  if ( IsDebuggerPresent() )
    exit(1);
  if ( sub_401543() )
    exit(1);
  hObject = CreateMutexA(0, 1, "Ipc::Critical::DontRemove");
  if ( !hObject )
    exit(1);
  CloseHandle(hObject);
  SetErrorMode(0x400u);
  if ( SetErrorMode(0) != 1024 )
    exit(1);
  lpAddress = (LPVOID)sub_401569(&unk_403040, dwSize);
  if ( !lpAddress )
    exit(3);
  sub_4015E5(lpAddress, dwSize);
  if ( !VirtualProtect(lpAddress, dwSize, 0x40u, &flOldProtect) )
  {
    VirtualFree(lpAddress, dwSize, 0x8000u);
    exit(4);
  }
  v3 = dwSize;
  CurrentProcess = GetCurrentProcess();
  FlushInstructionCache(CurrentProcess, lpAddress, v3);
  hHandle = CreateThread(0, 0, StartAddress, lpAddress, 0, ThreadId);
  WaitForSingleObject(hHandle, 0xFFFFFFFF);
  VirtualFree(lpAddress, dwSize, 0x8000u);
  return ThreadId[1];
}

void *__cdecl sub_401569(void *Src, size_t Size)
{
  SIZE_T dwPageSize; // eax
  _SYSTEM_INFO SystemInfo; // [esp+14h] [ebp-34h] BYREF
  void *v5; // [esp+38h] [ebp-10h]
  SIZE_T dwSize; // [esp+3Ch] [ebp-Ch]

  GetSystemInfo(&SystemInfo);
  dwPageSize = SystemInfo.dwPageSize;
  if ( Size >= SystemInfo.dwPageSize )
    dwPageSize = Size;
  dwSize = dwPageSize;
  v5 = VirtualAlloc(0, dwPageSize, 0x3000u, 4u);
  if ( v5 )
    return memcpy(v5, Src, Size);
  else
    return 0;
}

unsigned int __cdecl sub_4015E5(int a1, unsigned int a2)
{
  char v2; // al
  unsigned int result; // eax
  int i; // [esp+8h] [ebp-Ch]
  int k; // [esp+8h] [ebp-Ch]
  unsigned int j; // [esp+Ch] [ebp-8h]

  for ( i = 0x2000000; i; --i )
    ;
  for ( j = 0; ; ++j )
  {
    result = a2;
    if ( j >= a2 )
      break;
    v2 = byte_403020++;
    *(_BYTE *)(a1 + j) ^= v2;
  }
  for ( k = 0x2000000; k; --k )
    ;
  return result;
}
````

#### in windbg
First bypass IsDebuggerPresent and CheckNtGlobalFlag. During single-step debugging, r eax = 0 before ret. Then bp VirtualAlloc or memcpy. The second parameter of memcpy(v5, Src, Size) holds the SHELLCODE ENCODED address. When single-stepping to msvcrt!memcpy at address 0x75338CFB, esi contains the SHELLCODE ENCODED address and ecx is Size. Finally sub_4015E5 can also decrypt SHELLCODE ENCODED via XOR.
```asm
0:000> bl
     0 e Disable Clear  764d5570     0001 (0001)  0:**** KERNELBASE!VirtualAlloc

	KERNELBASE!VirtualAlloc+0x3b:
764d55ab ff156cf75976    call    dword ptr [KERNELBASE!_imp__NtAllocateVirtualMemory (7659f76c)] ds:002b:7659f76c={ntdll!NtAllocateVirtualMemory (77493340)}

	ntdll!NtAllocateVirtualMemory: CFG
77493340 b818000000     mov     eax, 18h
77493345 ba50914a77     mov     edx, 774A9150h
7749334a ffd2           call    edx
7749334c c21800         ret     18h

	msvcrt!memcpy: CFG
75338cf0 55             push    ebp
75338cf1 8bec           mov     ebp, esp
75338cf3 57             push    edi
75338cf4 56             push    esi
75338cf5 8b750c         mov     esi, dword ptr [ebp+0Ch]
75338cf8 8b4d10         mov     ecx, dword ptr [ebp+10h]
>> 75338cfb 8b7d08         mov     edi, dword ptr [ebp+8]
75338cfe 8bc1           mov     eax, ecx

0:000> db @esi L156
00403040  ef fc 97 16 17 18 79 93-fe 2d dd 7a 94 70 11 a9  ......y..-.z.p..
00403050  71 28 ae 74 33 a3 5b 02-24 9b 67 08 1e cf 9d 0e  q(.t3.[.$.g.....
00403060  52 48 37 1a 17 f9 f6 37-3a fb df cc 6d 17 ca 10  RH7....7:...m...
00403070  53 cf 0f 7a cc 04 58 32-a8 04 4c 9f 1e db 08 72  S..z..X2..L....r
00403080  52 87 de 1f 4f bb 63 13-d0 68 d6 5f 89 51 9e ce  R...O.c..h._.Q..
00403090  a2 ab 68 67 a0 50 89 1f-9d 6f 10 96 54 0d 55 07  ..hg.P...o..T.U.
004030a0  97 2c fe 2e 53 79 aa 1c-f0 70 36 f5 27 9c 80 51  .,..Sy...p6.'..Q
004030b0  08 80 0e 87 57 01 cd ae-af d7 d6 ef d6 ca c0 6d  ....W..........m
004030c0  73 cb ca cc 1c 8a 72 17-c6 f4 ae ac 9f a0 c9 d5  s.....r.........
004030d0  d0 96 fa f2 cf e4 de 8c-ac 25 45 51 7f 08 21 b3  .........%EQ..!.
004030e0  b3 b4 9c 72 e3 e8 d1 93-3b d7 bd 41 6a aa cb aa  ...r....;..Aj...
004030f0  6f d8 45 c3 af ca c9 db-97 45 2b 9e 9f 80 81 92  o.E......E+.....
00403100  83 94 85 be 3d d7 06 3a-24 09 4a b4 cf b6 b6 8a  ....=..:$.J.....
00403110  7a 41 91 87 18 3d 6c 2a-9f e6 12 a0 e7 85 1d 1a  zA...=l*........
00403120  94 f4 f5 f6 9d f8 93 fe-ad ab 95 fc 26 c8 5e fd  ............&.^.
00403130  d6 87 fd 06 79 3e 82 3c-61 4c 65 0e 1f 10 11 44  ....y>.<aLe....D
00403140  79 14 7d 4e b3 4b fc e5-ce 8f 4e 74 1f 76 72 75  y.}N.K....Nt.vru
00403150  4b 26 fc ee 78 d7 fc a9-d3 2c 50 06 77 58 31 72  K&..x....,P.wX1r
00403160  33 34 5f 36 67 50 32 15-34 0c c2 eb 68 28 34 2c  34_6gP2.4...h(4,
00403170  0e 25 ba 93 19 16 b6 46-6f 43 c8 3e b0 af ae bb  .%.....FoC.>....
00403180  c8 ab aa a9 56 9b 70 9c-2e 9d 9e e5 af d5 c3 34  ....V.p........4
00403190  09 64 36 99 b2 00                                .d6...
```
### Challenge：DUMP THE ENCRYPTION PASSWORD of MiniRansomware.run
Inspect loaded modules and PE header information.
```asm
0:000> lm
start             end                 module name
00000000`00400000 00000000`00667000   MiniRansomware T (no symbols)           
00007ffa`605d0000 00007ffa`607ac000   TTDRecordCPU   (deferred)             
00007ffa`83c70000 00007ffa`83c9d000   WINMMBASE   (deferred)             
00007ffa`83ca0000 00007ffa`83cc4000   winmm      (deferred)             
00007ffa`851a0000 00007ffa`8522f000   apphelp    (deferred)             
00007ffa`87010000 00007ffa`8705a000   cfgmgr32   (deferred)             
00007ffa`87060000 00007ffa`87303000   KERNELBASE   (deferred)             
00007ffa`87f80000 00007ffa`8807a000   ucrtbase   (deferred)             
00007ffa`88260000 00007ffa`88312000   KERNEL32 # (pdb symbols) 
00007ffa`88ff0000 00007ffa`8908e000   msvcrt     (deferred)             
00007ffa`892c0000 00007ffa`893e0000   RPCRT4     (deferred)             
00007ffa`895c0000 00007ffa`8962f000   ws2_32     (deferred)             
00007ffa`89fc0000 00007ffa`8a1b0000   ntdll    # (pdb symbols)

0:000> !dh 00000000`00400000

File Type: EXECUTABLE IMAGE
FILE HEADER VALUES
    8664 machine (X64)
       E number of sections
       0 time date stamp
  218600 file pointer to symbol table
     EE9 number of symbols
      F0 size of optional header

OPTIONAL HEADER VALUES
     20B magic #
    3.00 linker version
   B2200 size of code
   15A00 size of initialized data
       0 size of uninitialized data
   53000 address of entry point
    1000 base of code
         ----- new -----
0000000000400000 image base
    1000 section alignment
     200 file alignment
       3 subsystem (Windows CUI)
    4.00 operating system version
    1.00 image version
    4.00 subsystem version
  267000 size of image
     600 size of headers
       0 checksum
```
Dump the EXE file from memory.
```asm
0:000> .writemem MiniRansomware.exe 0x00400000 0x00667000-0x1
```
Since there are no symbols and the disassembly window doesn't show function names, try static analysis with IDA. MiniRansomware is a Go-compiled EXE. A bijection between function names and addresses was obtained from IDA. List all functions in in the main package.
```
Function name	Segment	Start	Length	Locals	Arguments				
main_DecodeStaticKey	.text	00000000004B1670	00000148	00000000	00000098
main_IsValidExtensions	.text	00000000004B17C0	000000FF	00000000	00000098
main_IsRegularFile	.text	00000000004B18C0	000000DC	00000020	00000098
main_EntryFunctionEncrypt	.text	00000000004B1E90	000002A1	00000000	00000098
main_DecryptFile	.text	00000000004B20E0	00000510	00000060	00000048
main_EntryFunctionDecrypt	.text	00000000004B25F0	0000003F	00000000	000000F0
main_AcceptSeriousWarning	.text	00000000004B27D0	00000260	00000000	00000151
main_main	.text	00000000004B2A30	0000037F	00000130	000000B8
main_init	.text	00000000004B2EC0	000000BD	00000120	00000021
```
Set breakpoints on all functions in the main package.
```asm
as main_DecodeStaticKey 4B1670
as main_IsValidExtensions 4B17C0
as main_IsRegularFile 4B18C0
as main_EntryFunctionEncrypt 4B1E90
as main_DecryptFile 4B20E0
as main_EntryFunctionDecrypt 4B25F0
as main_AcceptSeriousWarning 4B27D0
as main_main 4B2A30

bp main_DecodeStaticKey
bp main_IsValidExtensions    
bp main_IsRegularFile   
bp main_EntryFunctionEncrypt   
bp main_DecryptFile   
bp main_EntryFunctionDecrypt
bp main_AcceptSeriousWarning
bp main_main

0:000> bl
     0 e Disable Clear  00000000`004b1670     0001 (0001)  0:**** MiniRansomware+0xb1670
     1 e Disable Clear  00000000`004b17c0     0001 (0001)  0:**** MiniRansomware+0xb17c0
     2 e Disable Clear  00000000`004b18c0     0001 (0001)  0:**** MiniRansomware+0xb18c0
     3 e Disable Clear  00000000`004b1e90     0001 (0001)  0:**** MiniRansomware+0xb1e90
     4 e Disable Clear  00000000`004b20e0     0001 (0001)  0:**** MiniRansomware+0xb20e0
     5 e Disable Clear  00000000`004b25f0     0001 (0001)  0:**** MiniRansomware+0xb25f0
     6 e Disable Clear  00000000`004b27d0     0001 (0001)  0:**** MiniRansomware+0xb27d0
     7 e Disable Clear  00000000`004b2a30     0001 (0001)  0:**** MiniRansomware+0xb2a30
```
Press g (run), but execution doesn't enter main; instead, it halts at MiniRansomware+0xb1670 (0x4b1670). Cross-reference with IDA's bijection to confirm it's main_DecodeStaticKey.
```asm
0:000> g
Breakpoint 0 hit
Time Travel Position: FF5:2185
MiniRansomware+0xb1670:
00000000`004b1670 65488b0c2528000000 mov   rcx,qword ptr gs:[28h] gs:00000000`00000028=0000000000000000
```
Examine the disassembly of main_DecodeStaticKey.
```asm
004b1670 65488b0c2528000000 mov     rcx, qword ptr gs:[28h]
004b1679 488b8900000000     mov     rcx, qword ptr [rcx]
004b1680 483b6110           cmp     rsp, qword ptr [rcx+10h]
004b1684 0f861f010000       jbe     00000000004B17A9
004b168a 4883ec60           sub     rsp, 60h
004b168e 48896c2458         mov     qword ptr [rsp+58h], rbp
004b1693 488d6c2458         lea     rbp, [rsp+58h]
004b1698 48c744244800000000 mov     qword ptr [rsp+48h], 0
004b16a1 31c0               xor     eax, eax
004b16a3 eb03               jmp     00000000004B16A8
004b16a5 48ffc0             inc     rax
004b16a8 4883f808           cmp     rax, 8
004b16ac 7d56               jge     00000000004B1704
004b16ae 4885c0             test    rax, rax
004b16b1 7549               jne     00000000004B16FC
004b16b3 c644044830         mov     byte ptr [rsp+rax+48h], 30h
004b16b8 4883f805           cmp     rax, 5
004b16bc 7505               jne     00000000004B16C3
004b16be c64404486f         mov     byte ptr [rsp+rax+48h], 6Fh
004b16c3 4883f801           cmp     rax, 1
004b16c7 7505               jne     00000000004B16CE
004b16c9 c644044864         mov     byte ptr [rsp+rax+48h], 64h
004b16ce 4883f806           cmp     rax, 6
004b16d2 7505               jne     00000000004B16D9
004b16d4 c64404486e         mov     byte ptr [rsp+rax+48h], 6Eh
004b16d9 4883f802           cmp     rax, 2
004b16dd 7505               jne     00000000004B16E4
004b16df c644044865         mov     byte ptr [rsp+rax+48h], 65h
004b16e4 4883f803           cmp     rax, 3
004b16e8 7505               jne     00000000004B16EF
004b16ea c644044866         mov     byte ptr [rsp+rax+48h], 66h
004b16ef 4883f804           cmp     rax, 4
004b16f3 75b0               jne     00000000004B16A5
004b16f5 c644044863         mov     byte ptr [rsp+rax+48h], 63h
004b16fa eba9               jmp     00000000004B16A5
004b16fc 4883f807           cmp     rax, 7
004b1700 74b1               je      00000000004B16B3
004b1702 ebb4               jmp     00000000004B16B8
004b1704 31c0               xor     eax, eax
004b1706 31c9               xor     ecx, ecx
004b1708 31d2               xor     edx, edx
004b170a eb7f               jmp     00000000004B178B
004b170c 4889442438         mov     qword ptr [rsp+38h], rax
004b1711 48894c2450         mov     qword ptr [rsp+50h], rcx
004b1716 4889542440         mov     qword ptr [rsp+40h], rdx
004b171b 48c7042400000000   mov     qword ptr [rsp], 0
004b1723 488d442448         lea     rax, [rsp+48h]
004b1728 4889442408         mov     qword ptr [rsp+8], rax
004b172d 48c744241008000000 mov     qword ptr [rsp+10h], 8
004b1736 48c744241808000000 mov     qword ptr [rsp+18h], 8
004b173f e88cdbf8ff         call    000000000043F2D0
004b1744 488b442420         mov     rax, qword ptr [rsp+20h]
004b1749 488b4c2428         mov     rcx, qword ptr [rsp+28h]
004b174e 4889442418         mov     qword ptr [rsp+18h], rax
004b1753 48894c2420         mov     qword ptr [rsp+20h], rcx
004b1758 48c7042400000000   mov     qword ptr [rsp], 0
004b1760 488b442450         mov     rax, qword ptr [rsp+50h]
004b1765 4889442408         mov     qword ptr [rsp+8], rax
004b176a 488b442440         mov     rax, qword ptr [rsp+40h]
004b176f 4889442410         mov     qword ptr [rsp+10h], rax
004b1774 e857d9f8ff         call    000000000043F0D0
004b1779 488b442438         mov     rax, qword ptr [rsp+38h]
004b177e 48ffc0             inc     rax
004b1781 488b542430         mov     rdx, qword ptr [rsp+30h]
004b1786 488b4c2428         mov     rcx, qword ptr [rsp+28h]
004b178b 4883f804           cmp     rax, 4
004b178f 0f8c77ffffff       jl      00000000004B170C
004b1795 48894c2468         mov     qword ptr [rsp+68h], rcx
004b179a 4889542470         mov     qword ptr [rsp+70h], rdx
004b179f 488b6c2458         mov     rbp, qword ptr [rsp+58h]
004b17a4 4883c460           add     rsp, 60h
004b17a8 c3                 ret 
```
The final values processed by RCX and RDX are stored on the stack. The efficient approach is to first inspect RCX/RDX before analyzing details, or directly delegate to an LLM. Thus bp 004b1795.
```asm
0:000> bp 4b1795
0:000> g
Breakpoint 8 hit
Time Travel Position: FF6:3A4
MiniRansomware+0xb1795:
00000000`004b1795 48894c2468      mov     qword ptr [rsp+68h],rcx ss:000000c0`00065f78=00000000004c5060
0:000> db rcx L30
000000c0`0000c320  30 64 65 66 63 6f 6e 30-30 64 65 66 63 6f 6e 30  0defcon00defcon0
000000c0`0000c330  30 64 65 66 63 6f 6e 30-30 64 65 66 63 6f 6e 30  0defcon00defcon0
000000c0`0000c340  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0:000> db rdx L30
00000000`00000020  fc 59 3b aa 80 01 00 00-00 00 00 00 00 00 00 00  .Y;.............
00000000`00000030  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000000`00000040  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
0:000> da rcx
000000c0`0000c320  "0defcon00defcon00defcon00defcon0"
000000c0`0000c340  ""
```
main_DecodeStaticKey returned the value "0defcon00defcon00defcon00defcon0" on the stack. Continued execution (g), entering the main_main function, then stepping into main_AcceptSeriousWarning, and finally reaching main_EntryFunctionEncrypt.
```asm
0:000> g
Breakpoint 7 hit
Time Travel Position: FF8:3A
MiniRansomware+0xb2a30:
00000000`004b2a30 65488b0c2528000000 mov   rcx,qword ptr gs:[28h] gs:00000000`00000028=0000000000000000
0:000> g
Breakpoint 6 hit
Time Travel Position: 101B:14A1
MiniRansomware+0xb27d0:
00000000`004b27d0 65488b0c2528000000 mov   rcx,qword ptr gs:[28h] gs:00000000`00000028=0000000000000000
0:000> g
Breakpoint 3 hit
Time Travel Position: 1333:143D
MiniRansomware+0xb1e90:
00000000`004b1e90 65488b0c2528000000 mov   rcx,qword ptr gs:[28h] gs:00000000`00000028=0000000000000000 
```
Focused on analyzing the encryption/decryption logic of main_EntryFunctionEncrypt.
```asm
004b1e90 65488b0c2528000000 mov     rcx, qword ptr gs:[28h]
004b1e99 488b8900000000     mov     rcx, qword ptr [rcx]
004b1ea0 483b6110           cmp     rsp, qword ptr [rcx+10h]
004b1ea4 0f862c020000       jbe     00000000004B20D6
004b1eaa 4883ec78           sub     rsp, 78h
004b1eae 48896c2470         mov     qword ptr [rsp+70h], rbp
004b1eb3 488d6c2470         lea     rbp, [rsp+70h]
004b1eb8 488b842480000000   mov     rax, qword ptr [rsp+80h]
004b1ec0 48890424           mov     qword ptr [rsp], rax
004b1ec4 488b8c2488000000   mov     rcx, qword ptr [rsp+88h]
004b1ecc 48894c2408         mov     qword ptr [rsp+8], rcx
004b1ed1 e8eaf9ffff         call    00000000004B18C0
004b1ed6 488d442410         lea     rax, [rsp+10h]
004b1edb 803800             cmp     byte ptr [rax], 0
004b1ede 0f84dd010000       je      00000000004B20C1
004b1ee4 488b842480000000   mov     rax, qword ptr [rsp+80h]
004b1eec 48890424           mov     qword ptr [rsp], rax
004b1ef0 488b8c2488000000   mov     rcx, qword ptr [rsp+88h]
004b1ef8 48894c2408         mov     qword ptr [rsp+8], rcx
004b1efd e8aee2ffff         call    00000000004B01B0
004b1f02 488b442418         mov     rax, qword ptr [rsp+18h]
004b1f07 488b4c2410         mov     rcx, qword ptr [rsp+10h]
004b1f0c 4885c0             test    rax, rax
004b1f0f 7515               jne     00000000004B1F26
004b1f11 0f57c0             xorps   xmm0, xmm0
004b1f14 0f118424b0000000   movups  xmmword ptr [rsp+0B0h], xmm0
004b1f1c 488b6c2470         mov     rbp, qword ptr [rsp+70h]
004b1f21 4883c478           add     rsp, 78h
004b1f25 c3                 ret     
004b1f26 4883f804           cmp     rax, 4
004b1f2a 7508               jne     00000000004B1F34
004b1f2c 81392e656e63       cmp     dword ptr [rcx], 636E652Eh
004b1f32 74dd               je      00000000004B1F11
004b1f34 48890c24           mov     qword ptr [rsp], rcx
004b1f38 4889442408         mov     qword ptr [rsp+8], rax
004b1f3d e87ef8ffff         call    00000000004B17C0
004b1f42 488d442410         lea     rax, [rsp+10h]
004b1f47 803800             cmp     byte ptr [rax], 0
004b1f4a 74c5               je      00000000004B1F11
004b1f4c 488b842480000000   mov     rax, qword ptr [rsp+80h]
004b1f54 4889442440         mov     qword ptr [rsp+40h], rax
004b1f59 488b8c2488000000   mov     rcx, qword ptr [rsp+88h]
004b1f61 48894c2448         mov     qword ptr [rsp+48h], rcx
004b1f66 0f57c0             xorps   xmm0, xmm0
004b1f69 0f11442450         movups  xmmword ptr [rsp+50h], xmm0
004b1f6e 488d156b410100     lea     rdx, [4C60E0h]
004b1f75 48891424           mov     qword ptr [rsp], rdx
004b1f79 488d5c2440         lea     rbx, [rsp+40h]
004b1f7e 48895c2408         mov     qword ptr [rsp+8], rbx
004b1f83 e8d86ef5ff         call    0000000000408E60
004b1f88 488b442410         mov     rax, qword ptr [rsp+10h]
004b1f8d 488b4c2418         mov     rcx, qword ptr [rsp+18h]
004b1f92 4889442450         mov     qword ptr [rsp+50h], rax
004b1f97 48894c2458         mov     qword ptr [rsp+58h], rcx
004b1f9c 488d0596cb0300     lea     rax, [4EEB39h]
004b1fa3 48890424           mov     qword ptr [rsp], rax
004b1fa7 48c744240819000000 mov     qword ptr [rsp+8], 19h
004b1fb0 488d442450         lea     rax, [rsp+50h]
004b1fb5 4889442410         mov     qword ptr [rsp+10h], rax
004b1fba 48c744241801000000 mov     qword ptr [rsp+18h], 1
004b1fc3 48c744242001000000 mov     qword ptr [rsp+20h], 1
004b1fcc e8cfe6feff         call    00000000004A06A0
004b1fd1 488b842480000000   mov     rax, qword ptr [rsp+80h]
004b1fd9 48890424           mov     qword ptr [rsp], rax
004b1fdd 488b842488000000   mov     rax, qword ptr [rsp+88h]
004b1fe5 4889442408         mov     qword ptr [rsp+8], rax
004b1fea 488b842490000000   mov     rax, qword ptr [rsp+90h]
004b1ff2 4889442410         mov     qword ptr [rsp+10h], rax
004b1ff7 488b842498000000   mov     rax, qword ptr [rsp+98h]
004b1fff 4889442418         mov     qword ptr [rsp+18h], rax
004b2004 e857f9ffff         call    00000000004B1960
004b2009 488d442420         lea     rax, [rsp+20h]
004b200e 803800             cmp     byte ptr [rax], 0
004b2011 747f               je      00000000004B2092
004b2013 488d05838b0300     lea     rax, [4EAB9Dh]
004b201a 48890424           mov     qword ptr [rsp], rax
004b201e 48c744240807000000 mov     qword ptr [rsp+8], 7
004b2027 48c744241000000000 mov     qword ptr [rsp+10h], 0
004b2030 0f57c0             xorps   xmm0, xmm0
004b2033 0f11442418         movups  xmmword ptr [rsp+18h], xmm0
004b2038 e863e6feff         call    00000000004A06A0
004b203d 0f57c0             xorps   xmm0, xmm0
004b2040 0f11442460         movups  xmmword ptr [rsp+60h], xmm0
004b2045 488d0594400100     lea     rax, [4C60E0h]
004b204c 4889442460         mov     qword ptr [rsp+60h], rax
004b2051 488d05280a0500     lea     rax, [502A80h]
004b2058 4889442468         mov     qword ptr [rsp+68h], rax
004b205d 488d442460         lea     rax, [rsp+60h]
004b2062 48890424           mov     qword ptr [rsp], rax
004b2066 48c744240801000000 mov     qword ptr [rsp+8], 1
004b206f 48c744241001000000 mov     qword ptr [rsp+10h], 1
004b2078 e8b3e9feff         call    00000000004A0A30
004b207d 0f57c0             xorps   xmm0, xmm0
004b2080 0f118424b0000000   movups  xmmword ptr [rsp+0B0h], xmm0
004b2088 488b6c2470         mov     rbp, qword ptr [rsp+70h]
004b208d 4883c478           add     rsp, 78h
004b2091 c3                 ret     
004b2092 488d05c2880300     lea     rax, [4EA95Bh]
004b2099 48890424           mov     qword ptr [rsp], rax
004b209d 48c744240806000000 mov     qword ptr [rsp+8], 6
004b20a6 48c744241000000000 mov     qword ptr [rsp+10h], 0
004b20af 0f57c0             xorps   xmm0, xmm0
004b20b2 0f11442418         movups  xmmword ptr [rsp+18h], xmm0
004b20b7 e8e4e5feff         call    00000000004A06A0
004b20bc e97cffffff         jmp     00000000004B203D
004b20c1 0f57c0             xorps   xmm0, xmm0
004b20c4 0f118424b0000000   movups  xmmword ptr [rsp+0B0h], xmm0
004b20cc 488b6c2470         mov     rbp, qword ptr [rsp+70h]
004b20d1 4883c478           add     rsp, 78h
004b20d5 c3                 ret 
```
For call instructions, query IDA's bijection mapping.
```
00000000004B18C0: main_IsRegularFile
00000000004B01B0: path_filepath_Ext
00000000004B17C0: main_DecodeStaticKey
0000000000408E60: runtime_convT2Estring
00000000004A06A0: fmt_Printf
00000000004B1960: Located in the main package between main_IsRegularFile and main_EntryFunctionEncrypt
00000000004A0A30: Located in the fmt package between fmt_Fprint and fmt_Fprintln
```
Set breakpoints on the last two calls and resumed execution (g). Dynamic analysis revealed a tight loop between main_EntryFunctionEncrypt and main_IsRegularFile, indicating iterative file validation. After removing breakpoints from these functions and continuing execution (g), the process entered another loop at main_IsValidExtensions. Subsequent breakpoint removal and continuation (g) allowed progression beyond file filtering stages.
```asm
bp 4B1960
bp 4A0A30
bc 3
bc 4
bc 2
```
Execution halts at `call 00000000004B1960`. Step into the function. Again, for subsequent call instructions, query IDA's bijection mapping.
```
00000000004B11E0: io_ioutil_ReadFile
00000000004A06A0: fmt_Printf
000000000043F470: Located between runtime.concatstring5 and runtime_stringtoslicerune
000000000046D910: crypto_aes_NewCipher
000000000043B3C0: runtime_makeslice
00000000004622E0: Located between crypto_cipher__ptr_cfb_XORKeyStream and crypto_cipher_NewCFBDecrypter
000000000043F0D0: runtime_concatstring2
00000000004B1380: io_ioutil_WriteFile
And two call rax instructions require runtime debugging to resolve
```
The function at 46D910 corresponds to crypto_aes_NewCipher, whose sole parameter is the encryption key. Therefore, bp 004b1b09 and db the key.
```asm
0:000> db [rsp]
000000c0`00065378  28 54 06 00 c0 00 00 00-20 00 00 00 00 00 00 00  (T...... .......
000000c0`00065388  20 00 00 00 00 00 00 00-08 54 06 00 c0 00 00 00   ........T......
000000c0`00065398  10 00 00 00 00 00 00 00-20 00 00 00 00 00 00 00  ........ .......
000000c0`000653a8  00 00 00 00 00 00 00 00-d8 53 06 00 c0 00 00 00  .........S......
000000c0`000653b8  27 03 4a 00 00 00 00 00-2c 0d 00 00 00 00 00 00  '.J.....,.......
000000c0`000653c8  2c 0f 00 00 00 00 00 00-20 00 00 00 00 00 00 00  ,....... .......
000000c0`000653d8  20 00 00 00 00 00 00 00-10 00 00 00 00 00 00 00   ...............
000000c0`000653e8  20 00 00 00 00 00 00 00-00 20 07 00 c0 00 00 00   ........ ......
0:000> db poi[rsp]
000000c0`00065428  30 64 65 66 63 6f 6e 30-30 64 65 66 63 6f 6e 30  0defcon00defcon0
000000c0`00065438  30 64 65 66 63 6f 6e 30-30 64 65 66 63 6f 6e 30  0defcon00defcon0
000000c0`00065448  00 b0 06 00 c0 00 00 00-28 54 06 00 c0 00 00 00  ........(T......
000000c0`00065458  08 54 06 00 c0 00 00 00-39 eb 4e 00 00 00 00 00  .T......9.N.....
000000c0`00065468  19 00 00 00 00 00 00 00-00 55 06 00 c0 00 00 00  .........U......
000000c0`00065478  01 00 00 00 00 00 00 00-01 00 00 00 00 00 00 00  ................
000000c0`00065488  92 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000000c0`00065498  00 00 00 00 00 00 00 00-20 55 06 00 c0 00 00 00  ........ U......
```
