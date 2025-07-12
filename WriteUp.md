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
