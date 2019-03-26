---
title: X-NUCA（全国高校网安联赛）2018 Code Interpreter 解题报告（writeup）
date: 2018-11-25 23:42:57
tags:
- Writeups
- CTF
- 信息安全
---

### 0x0. 前言

8 个人只做出了这唯一的一道题，太惨了... 不过第一次做虚拟机的题，做出来很开心。有道密码学热身题是 RSA，解出来的人多到都降分到 100+ 了，还是不会解，我真的好菜。另外一道逆向题看了下，想起和看雪 CTF 的叹息之墙很像，搜了一下，发现这种混淆叫做[控制流平坦化](https://zhuanlan.zhihu.com/p/33641488)（control flow flattening），第一次见，解不出来。用了腾讯实验室的脚本 [deflat.py](https://security.tencent.com/index.php/opensource/detail/18) 恢复控制流好像也有点问题。总之就还有很多要学...

### 0x1. Code Interpreter

直接拖进 IDA，进 `main()` 函数看，程序先验证命令行参数个数大于 1，然后将第二个参数作为文件名打开，分配一块与此文件大小相同的缓冲区 `buf`，把文件内容读到里面。接着提示输入三个数 `first`, `second`, `third`。再把缓冲区 `buf` 指针传进函数 `sub_400806` 中，该函数执行结束后，判断全局变量 `dword_6024B0` 为 0、`first` 和 `third` 的低八位为 0x5E、`second` 的 16~23 位为 0x5E，满足则打印成功并回显 flag。

由于上述四个全局变量没有在 `main()` 函数中修改，因此只能是在 `sub_400806` 中修改了。接下来分析 `sub_400806`。

一开始先设置了一些全局变量，尤其是把刚输入的三个数依次存进了 `dword_6020A0` 数组中，具体什么意思还不清楚，先往下看。一个 `while` 循环套一个 `switch`，`switch` 括号里的东西是 `buf[dword_4024B4]`，因此很明显 `dword_4024B4` 是 `buf` 的偏移指针。

再看各个 case，大致浏览了下，`default` 分支会打印出 `Invalid opcode!` 这个字符串，意思是无效操作码，很明显（如题目名字）这是一个代码解释器，解释 `buf` 里的 opcode。

`case 0` 分支只是将变量 `v16` 设为 0，这样下一次循环就会退出，可以视为停机操作 `hlt`。

`case 1` 分支先取指令中第二和第三字节拼接起来，再取第四第五字节和前者再拼接形成一个 DWORD，把这个 DWORD 存到数组 `dword_6020A0` 中，同时 `dword_6024B8` 加一。可以猜测，`dword_6020A0` 相当于一个栈，`dword_6024B8` 是栈顶指针。这样，`case 1` 的作用是 `push 立即数（小尾序）`。

`case 2` 将栈顶指针减一，可以说相当于 `pop`，但没有返回栈顶元素。

`case 3` 使 `dword_6024A0[指令第二字节] += dword_6024A0[指令第三字节]`，相当于 `add`，`dword_6024A0` 是一个数组，有 5 个 `int` 元素，`dword_6024A0[4]` 其实就是 `main()` 里面判断的 `dword_6024B0`。

`case 4` 使 `dword_6024A0[指令第二字节] -= dword_6024A0[指令第三字节]`，相当于 `sub`。

`case 5` 使 `dword_6024A0[指令第二字节] *= 指令第三字节`，相当于 `mul [内存], 立即数`。

`case 6` 使 `dword_6024A0[指令第二字节] >>= 指令第三字节`，相当于 `shr [内存], 立即数`。

`case 7` 使 `dword_6024A0[指令第二字节] = dword_6024A0[指令第三字节]`，相当于 `mov`。

`case 8` 使 `dword_6024A0[指令第二字节] = 栈[dword_6024A0[指令第三字节]]`，也相当于 `mov` 但是从栈上 `mov`。

`case 9` 使 `dword_6024A0[指令第二字节] ^= dword_6024A0[指令第三字节]`，相当于 `xor`。

`case 10` 使 `dword_6024A0[指令第二字节] |= dword_6024A0[指令第三字节]`，相当于 `or`。

到此全部 opcode 分析完，接着要按题目给出的 code 文件里的内容解析指令，应该可以写脚本解析，但是我手工解析的，这是个机械的过程，这里不说了，解析完是这样（我翻译成的 C 伪代码）：

```c
e = 0;
a = 0;
b = first;
c = second;
d = third;
b >>= 4;
b *= 0x15;
a = b;
a -= d;
push 0x1d7ecc6b
b = pop();
a -= b;
e |= a;
a = 0;
b = first;
c = second;
d = third;
d >>= 8;
d *= 3;
a = d;
a += c;
push 0x6079797c
b = pop();
a -= b;
e |= a;
a = 0;
b = first;
c = second;
d = third;
b >>= 8;
a = b;
a += c;
push 0x5fbcbdbd
b = pop();
a -= b;
e |= a;
```

最后要求 `e == 0` 才能通过 `main()` 函数的判断，整理一下上面代码，`e` 的表达式可以写成一句：

```c
e = ((first >> 4) * 0x15 - third - 0x1d7ecc6b) | ((third >> 8) * 3 + second - 0x6079797c) | ((first >> 8) + second - 0x5fbcbdbd)
```

再加上 `main()` 里的另外三条约束条件：

```c
(second & 0xff0000) == 0x5e0000
(first & 0xff) == 0x5e
(third & 0xff) == 0x5e
```

有这些方程就足够解出要输入的三个数 first, second, third，写脚本用 Z3 求解即可，脚本如下：

```python
import sys
sys.path.append('z3/build/')
from z3 import *

s = Solver()

first = BitVec('first',32)
second = BitVec('second',32)
third = BitVec('third',32)

s.add(((first >> 4) * 0x15 - third - 0x1d7ecc6b) | ((third >> 8) * 3 + second - 0x6079797c) | ((first >> 8) + second - 0x5fbcbdbd) == 0)
s.add((second & 0xff0000) == 0x5e0000)
s.add((first & 0xff) == 0x5e)
s.add((third & 0xff) == 0x5e)

print(s.check())
mod = s.model()

chars = [
          mod[first],
          mod[second],
          mod[third]
        ]

print chars
```

运行脚本：

![](https://i.loli.net/2018/11/25/5bfac469c6fbd.png)

将这三个数输入到题目程序中就得到 flag：
$$
X-NUCA\{5e5f5e5e5f5e5e5f5e5e5f5e\}
$$
![](https://i.loli.net/2018/11/25/5bfac46a8746f.png)