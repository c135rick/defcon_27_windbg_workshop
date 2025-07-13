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
