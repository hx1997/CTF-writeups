---
title: 安恒杯 7 月月赛逆向第二题解题报告（writeup）
date: 2018-07-22 16:05:34
tags:
- 信息安全
- CTF
- Writeup
---

### 0x0. 前言

这次这道题 100 分，但是大家都说比上个月 500 分的题还难。其实我比赛时也没做出来，之后才做出来的，毕竟下午三点才开始做...

### 0x1. 反调试 

题目文件在[这里](https://github.com/hx1997/CTF-writeups/raw/master/anheng-july-re-youngter-drive/Youngter-drive.exe)。

查壳，是 UPX，直接用 `upx -d` 命令脱壳，结果运行不起来。发现是原文件需要 msvcr100d.dll 这个库，而且这是 Debug 版本的库，光装 VC++ 运行时是没有的，要装 Visual Studio，还必须是 2010 版... 网上下了个 msvcr100d.dll 放到同一目录下，原文件可以运行了，脱壳后的还是不行... 不管了，脱壳版用 IDA 静态分析，原文件用来运行测试吧。

首先，程序有反调试，先解决掉这个。（反调试其实是分析到一半才发现的，这里为了写文章的逻辑，先说了，而且后面其实也不怎么用到 OD 调试...）

反调试的表现是，用 OD 载入程序，还**没进入主函数的逻辑**，就打印出 `///////\nWARNING\n///////\n`，立马退出了。把脱壳文件拖进 IDA，按 Shift+F12 查看字符串，果然有这串：

![IDA 查看警告字符串](//wx3.sinaimg.cn/large/6b1e58d5gy1ftisfe69e9j20gh04zt8y.jpg)

双击，然后按 Ctrl+X 看有哪些函数引用了这条字符串，有两个，先看靠前的那个。函数里有很多 `ollydbg.exe`、`ida.exe` 这样的字符串，还有 `CreateToolhelp32Snapshot` 之类的 API 调用，很明显是遍历系统进程，检测有没有调试工具在运行。再看靠后的那个，这个函数很有意思，学到了点东西，我把反汇编结果贴出来：

```assembly
.text:004117AE                 mov     [ebp+var_8], 0
.text:004117B5                 mov     eax, large fs:30h
.text:004117BB                 db      3Eh
.text:004117BB                 movzx   eax, byte ptr [eax+2]
.text:004117C0                 mov     [ebp+var_8], eax
.text:004117C3                 cmp     [ebp+var_8], 0
.text:004117C7                 jz      short loc_4117F1
.text:004117C9                 mov     esi, esp
.text:004117CB                 push    offset aWarning_0 ; "///////\nWARNING\n///////\n"
.text:004117D0                 call    ds:printf
.text:004117D6                 add     esp, 4
.text:004117D9                 cmp     esi, esp
.text:004117DB                 call    sub_41116D
.text:004117E0                 mov     esi, esp
.text:004117E2                 push    0               ; Code
.text:004117E4                 call    ds:exit
```

第二行把 `fs:30h` 传送到 eax，在 x86 Windows 上，fs 寄存器指向一个结构体，叫做 TIB（Thread Information Block，线程信息块）[^1]。其偏移 0x30 处是 PEB（Process Environment Block，进程环境块）的地址[^2]。所以第二行执行后，eax 里寄存的就是 PEB 结构体的地址。

第四行把 eax+2 当作字节指针（即指向的数据是以字节为单位），其指向的那个字节的内容零扩展后传送到 eax，相当于 C 语言的 `eax = *((char *)(eax + 2));`。eax+2 就是 PEB+2，这个位置是一个叫做 `BeingDebugged` 的标志位，指示当前进程是否处于被调试状态[^3]。

第五行到第七行把 eax 的值存到局部变量里，然后和 0 比较，如果不等于 0 就继续往下执行 `004117C9` 处以及后面的指令，如果等于 0 就跳到 `loc_4117F1` 处（上面汇编代码未节选）执行。注意最后一行调用 `exit` 会让程序退出，所以只有 eax == 0 才能让程序继续运行，也就是 `BeingDebugged` 标志位要是 0，表示程序未被调试。

要怎么绕过反调试呢？理论上可以在 OD 调试的时候动态修改判断逻辑，让程序绕过反调试继续运行，不过我还不会调试 TLS 回调，所以还是用 IDA patch 了。在这之前先搞清楚这两个反调试函数是怎么被调用的，在它们俩中任意一个的函数名上按 Ctrl+X，可以查到哪个函数是调用方，中间有一个只有一句 `jmp` 的过渡函数，再往回追查调用方就看到是一个名为 `TlsCallback_0_0` 的函数调用了反调试函数。看到这名字就知道是 TLS 回调函数，具体可以上网搜，这里不多说了，知道操作系统会调用这个函数就行了。

现在要解决掉 TLS 回调，用 IDA 载入原文件，发现 TLS 回调函数没有被 UPX 加壳，可以直接 patch。最开始的想法是用 CFF Explorer 之类的 PE 文件工具把存储了 TLS 回调函数指针的 TLS 目录删掉，这样就用不着 IDA patch，结果发现还是会触发反调试，不是很懂。第二个想法是 `nop` 掉回调函数里所有的 `call` 指令，这样就不会调用反调试函数，结果 patch 后程序运行崩溃... 最后我的办法是把回调函数开头直接改成 `ret`，成功了。Patch 之后是这样的（最后一行是原本的函数结尾，现在函数一开始就结束了）：

```assembly
UPX1:0041F176                 public TlsCallback_0
UPX1:0041F176 TlsCallback_0   proc near               ; DATA XREF: UPX1:TlsCallbackso
UPX1:0041F176                 retn    0Ch
UPX1:0041F176 TlsCallback_0   endp
UPX1:0041F176
UPX1:0041F179 ; ---------------------------------------------------------------------------
UPX1:0041F179                 mov     esi, (offset dword_411140+45E0h)
UPX1:0041F17E                 cld
UPX1:0041F17F
UPX1:0041F17F loc_41F17F:                             ; CODE XREF: UPX1:0041F18Fj
UPX1:0041F17F                 lodsd
UPX1:0041F180                 test    eax, eax
UPX1:0041F182                 jz      short loc_41F191
UPX1:0041F184                 push    3
UPX1:0041F186                 pop     ecx
UPX1:0041F187
UPX1:0041F187 loc_41F187:                             ; CODE XREF: UPX1:0041F18Bj
UPX1:0041F187                 push    dword ptr [esp+10h]
UPX1:0041F18B                 loop    loc_41F187
UPX1:0041F18D                 call    eax
UPX1:0041F18F                 jmp     short loc_41F17F
UPX1:0041F191 ; ---------------------------------------------------------------------------
UPX1:0041F191
UPX1:0041F191 loc_41F191:                             ; CODE XREF: UPX1:0041F182j
UPX1:0041F191                 pop     esi
UPX1:0041F192                 retn    0Ch
```

### 0x2. 程序主体分析

运行程序观察行为，提示输入 flag，随便输入一串，程序退出了。在 IDA 里找字符串 `input flag:`，可以迅速定位到函数 `sub_411BD0`，按 F5 看伪代码：

```c
int sub_411BD0()
{
  char v1; // [sp+Ch] [bp-C0h]@1

  memset(&v1, 0xCCu, 0xC0u);
  printf("1111111111111111111111111111111111111111111111111111111111111111111111111111111\n\n");
  sub_41116D();
  printf("input flag:\n");
  sub_41116D();
  scanf("%36s", &Source);
  sub_41116D();
  return sub_41116D();
}
```

第一句 printf 打印的东西很长，又没什么用，我省略了一些。可以看到这个函数就只是把输入的 flag 存到全局缓冲区 `Source` 里面，而且最多只存 36 个字符（还特意看了下大小，没有溢出）。`sub_41116D` 貌似是 C 运行时库里面检查堆栈平衡破坏的函数，不用管。

没什么有趣的地方了，往上追溯调用方，来到 `sub_411C70`，这应该就是 `main` 函数了，因为再往上似乎是运行时库的领域了。按 F5 看伪代码：

```c
int sub_411C70()
{
  char v1; // [sp+Ch] [bp-D8h]@1
  HANDLE v2; // [sp+D0h] [bp-14h]@1
  HANDLE hObject; // [sp+DCh] [bp-8h]@1

  memset(&v1, 0xCCu, 0xD8u);
  sub_4110FF();
  CreateMutexW(0, 0, 0);
  ::hObject = (HANDLE)sub_41116D();
  j_strcpy(Dest, &Source);
  CreateThread(0, 0, StartAddress, 0, 0, 0);
  hObject = (HANDLE)sub_41116D();
  CreateThread(0, 0, sub_41119F, 0, 0, 0);
  v2 = (HANDLE)sub_41116D();
  CloseHandle(hObject);
  sub_41116D();
  CloseHandle(v2);
  sub_41116D();
  while ( dword_418008 != -1 )
    ;
  sub_411190();
  CloseHandle(::hObject);
  sub_41116D();
  return sub_41116D();
}
```

事情似乎变得有趣了，`CreateThread` API 会创建新线程，这道题涉及到多线程。`CreateMutex` 创建一个[互斥体](https://zh.wikipedia.org/wiki/%E4%BA%92%E6%96%A5%E9%94%81)，用于防止多线程中出现资源争用，即多个线程同时读写同一个资源的情况，所创建的互斥体的句柄会存到全局变量 `hObject` 中（注意前面的两个冒号表示是全局变量，而不是这个函数里同名的局部变量）。这里创建了两个线程，入口点分别位于函数 `StartAddress` 和 `sub_41119F`，且这两个函数都没有传入参数，看看 `StartAddress` 的伪代码（`sub_41119F` 的代码高度相似，只是没有 `sub_41112C` 的那句）：

```c
void __stdcall StartAddress_0(int a1)
{
  char v1; // [sp+Ch] [bp-C0h]@1

  memset(&v1, 0xCCu, 0xC0u);
  while ( 1 )
  {
    WaitForSingleObject(hObject, 0xFFFFFFFF);
    sub_41116D();
    if ( dword_418008 > -1 )
    {
      sub_41112C(&Source, dword_418008);
      --dword_418008;
      Sleep(0x64u);
      sub_41116D();
    }
    ReleaseMutex(hObject);
    sub_41116D();
  }
}
```

查 MSDN 知，可以用 `WaitForSingleObject` 等待互斥体的使用权（ownership）空闲出来，并获取使用权，然后再访问和其他线程共享的资源，访问完后，用 `ReleaseMutex` 释放使用权，给其他线程使用的机会[^4]。通过比较两线程的函数，很容易知道所共享的资源就是全局变量 `dword_418008`，它的初值是 29。而这两个线程一前一后创建，但是由于操作系统对线程的调度取决于当时的环境，我们似乎没有办法预知哪个线程先执行（也可能可以预知，多线程方面实在不太会）。假设是 `StartAddress` 先获得使用权，后来的 `sub_41119F` 进入等待状态，前者执行一次循环后释放使用权，与此同时后者等待结束、获得使用权，进入循环，循环完后释放使用权，前者又获得使用权，如此循环往复。也就是说，两个线程的操作是交替进行的。

那么调用的 `sub_41112C` 这个函数有什么用呢？既然传入了 `Source` 缓冲区的指针，也就是传入了输入的 flag，那肯定是要对 flag 进行某种变换，很大可能会把变换后的结果和某个预先设定的值比较，相等就提示 flag 输入正确。

来到 `sub_411940`（`sub_41112C` 是过渡函数，直接 `jmp` 到这里），打算看伪代码，结果报错：

> Decompilation failure:
>
> 411A03: positive sp value has been found

网上搜了下，说是 IDA 识别出错，堆栈不平衡了。所谓堆栈平衡，就是说在函数开始和结束时，栈顶指针 SP 必须指向同一个地方，否则称为堆栈不平衡或堆栈平衡破坏。我们知道函数的局部变量是在栈上分配，所谓分配其实就是抬高栈顶，减少 SP 的值，划出一块内存空间给局部变量用。函数结束时，要回收分配的空间，也就是降低栈顶，增加 SP 的值。当时分配了多少空间，就应当回收多少，因此 SP 指向的地方应当是不变的。IDA 的做法是在函数开始时，假设 SP 为 0，函数中间可能会增减 SP，最后结束时 SP 应当回到 0，而这里 IDA 识别出现了错误，SP 大于 0，因此报错。这种情况下一般有两种办法：一是直接看汇编，不看伪代码了，IDA 的反汇编还是有保证的；二是手动修复 SP。我选择了后者。

点 Options 菜单里第一项 General，在打开的对话框里勾选 Stack pointer，这样会在每一行汇编指令左边显示出该句执行前的 SP。拉到 `sub_411940` 的汇编底部，点击 SP 值异常的前面那一句，如下图，按 Alt+K：

![修复 SP 指针](//wx2.sinaimg.cn/large/6b1e58d5gy1ftk7t1dam5j20ay07vq2v.jpg)

在弹出的对话框里输入 `0x0`，确定，然后再点击下一句，同样按 Alt+K，输 `0x0`，确定。这样最后两句的 SP 都变成了 0，此时可以按 F5 看伪代码了：

```c
int __cdecl sub_411940(int a1, int a2)
{
  char v3; // [sp+Ch] [bp-CCh]@1
  char v4; // [sp+D3h] [bp-5h]@1

  memset(&v3, 0xCCu, 0xCCu);
  v4 = *(_BYTE *)(a2 + a1);
  if ( (v4 < 'a' || v4 > 'z') && (v4 < 'A' || v4 > 'Z') )
    exit(0);
  if ( v4 < 'a' || v4 > 'z' )
    *(_BYTE *)(a2 + a1) = off_418000[0][*(_BYTE *)(a2 + a1) - 38];
  else
    *(_BYTE *)(a2 + a1) = off_418000[0][*(_BYTE *)(a2 + a1) - 96];
  return sub_41116D();
}
```

参数 `a1` 是 `Source` 的指针，`a2` 是计数值 `dword_418008`，`*(_BYTE *)(a1 + a2)` 其实就是取输入 flag 里第 `a2 + 1` 个字符（的 ASCII 码）。计数值从 29 开始，线程循环每执行一次减一，减到 0 为止，这里有坑，并不是计数值每减一都会调用一次这个函数。前面说过，两个线程是**交替执行**的，`StartAddress` 会调用这个函数，然后计数值减一，但 `sub_41119F` 不会调用这个函数，直接把计数值减一。这意味着输入的 flag 里只有一半的字符会被变换，其余的一半不会变。这函数里先判断了下字符是不是字母再变换，大写字母变换成 `off_418000[0][*(_BYTE *)(a2 + a1) - 38]`，小写字母变换成 `off_418000[0][*(_BYTE *)(a2 + a1) - 96]`，其中 `off_418000[0]` 是一个字符串，内容是 `QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm`。需要注意的一点是，变换后的字符串末尾应该有结束符，也就是说，输入的 flag 应该比变换后的字符串多一个字符，因为多出来的那个字符经过变换会变成结束符。

知道 flag 的变换规则后，我们可以回到 `main` 函数，看最后调用的 `sub_411190` 了。这也是个过渡函数，直接跳转到 `sub_411880`，再次遇到了 SP 指针错误的问题，用同样的方法修复，然后看伪代码：

```c
int sub_411880()
{
  char v1; // [sp+Ch] [bp-CCh]@1
  int i; // [sp+D0h] [bp-8h]@1

  memset(&v1, 0xCCu, 0xCCu);
  for ( i = 0; i < 29; ++i )
  {
    if ( *(&Source + i) != off_418004[i] )
      exit(0);
  }
  printf("\nflag{%s}\n\n", Dest);
  sub_41116D();
  return sub_41116D();
}
```

很简单的逻辑，把变换后的字符串每一位和预设的 `off_418004` 字符串的每一位比较，全部相同就回显出 flag，表明你输入的 flag 正确。上述预设字符串的内容是 `TOiZiZtOrYaToUwPnToBsOaOapsyS`。到此程序的全部逻辑已经清楚，就是输入的 flag 经过变换后等于前面这串字符串的话，就是正确的 flag，我们只需要从这串字符串反推出正确 flag 就行了。写了段 C 程序来做这个工作，因为不知道哪个线程先执行，所以有两种可能，分别对应代码里 `i % 2 == 0` 或 `i % 2 == 1`，都试过后发现前者给出的 flag 明显是有意义的字符串，所以答案大概就是它了。C 程序如下：

```c
#include <stdio.h>
#include <string.h>

int isalpha(char a) {
	return (a >= 'a' && a <= 'z') || (a >= 'A' && a <= 'Z');
}

int map(char ch, char *str) {
	char buf[2] = {ch, 0};
	return (strstr(str,buf) - str);
}

int main(void) {
	char str1[] = "TOiZiZtOrYaToUwPnToBsOaOapsyS";
	char str2[] = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm";
	
	for (int i = 0; i < 29; i++) {
		// threads run alternately; so only half of the input will be transformed.
		if (i % 2 == 0) {
			putchar(str1[i]);
			continue;
		}
		if (isalpha(map(str1[i], str2) + 38))
			putchar(map(str1[i], str2) + 38);
		else
			putchar(map(str1[i], str2) + 96);
	}
	
	// find out the character that will be transformed into NULL byte.
	if (isalpha(strlen(str2) + 38))
		putchar(strlen(str2) + 38);
	else
		putchar(strlen(str2) + 96);
	
	return 0;
}
```

最后 flag：
$$
flag\{ThisisthreadofwindowshahaIsESZ\}
$$
![flag](//wx1.sinaimg.cn/large/6b1e58d5gy1ftk7rr9c3wj20qh0htdg5.jpg)

### 0x3. 参考资料

[^1]: D. Yurichev, “缓冲区溢出的保护方法,” in *《逆向工程权威指南》*, Archer and 安天安全研究与应急处理中心, Trans. 北京：人民邮电出版社, 2017, pp. 236.
[^2]: [https://en.wikipedia.org/wiki/Win32_Thread_Information_Block](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)
[^3]: [https://docs.microsoft.com/zh-cn/windows/desktop/api/winternl/ns-winternl-\_peb](https://docs.microsoft.com/zh-cn/windows/desktop/api/winternl/ns-winternl-\_peb)
[^4]: [https://docs.microsoft.com/zh-cn/windows/desktop/Sync/using-mutex-objects](https://docs.microsoft.com/zh-cn/windows/desktop/Sync/using-mutex-objects)