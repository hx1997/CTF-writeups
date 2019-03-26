---
title: 中科大第五届信息安全大赛部分解题报告（writeup）
date: 2018-10-16 22:44:30
tags:
- 信息安全
- CTF
- Writeups
---

### 0x0. 前言

作为校外其他组参赛，最后[总排名 94](https://hack.lug.ustc.edu.cn/board/)，其他高校组排名 69，我还是好菜啊。

### 0x1. 猫咪和键盘 150

题目是一个 C++ 源文件，似乎每一行的顺序被打乱了，但各行打乱的规律都是相同的。

![](https://i.loli.net/2018/10/16/5bc5fc159062c.png)

写 Python 脚本逐行恢复原本顺序。

```python
newline = ''
for line in open('./typed_printf.cpp'):
    newline += line[0]
    newline += line[32:39]
    newline += line[1:7]
    newline += line[20:22]
    newline += line[8:20]
    newline += line[22:32]
    newline += line[39:]

print newline
```

将输出重定向到新文件 `typed.cpp`，按注释里的提示，用 g++ 7 编译：

```bash
g++-7 -std=c++17 typed.cpp
```

运行后打印出 flag：
$$
flag\{FfQ47if9Zxw9jXE68VtGAJDk6Y6Xc88UrUtpK3iF8p7BMs4y2gzdG8Ao2gv6aiJ125typed\_printf95\}
$$


### 0x2. 猫咪遥控器 200

题目提示上下左右，又有一段猫追着激光点跑的视频，猜测是根据给出的文件里面的上下左右方向画图。写了段 C 程序来画：

```c
#include <stdio.h>
#include <string.h>

#define N 150
#define M 600

char map[N][M];

void up(int *x, int *y) {
	map[(*x)--][*y] = '!';
}

void down(int *x, int *y) {
	map[(*x)++][*y] = '!';
}

void left(int *x, int *y) {
	map[*x][(*y)--] = '!';
}

void right(int *x, int *y) {
	map[*x][(*y)++] = '!';
}

int main() {
	char buf[4000];
	
	for (int i = 0; i < N; i++)
		for (int j = 0; j < M; j++)
			map[i][j] = '.';
	
	int x = 0, y = 0;
	scanf("%s", buf);
	for (int i = 0; i < strlen(buf); i++) {
		switch (buf[i]) {
			case 'U': up(&x, &y); break;
			case 'D': down(&x, &y); break;
			case 'L': left(&x, &y); break;
			case 'R': right(&x, &y); break;
		}
	}
	
	for (int i = 0; i < M; i++) {
		for (int j = 0; j < N; j++)
			putchar(map[j][i]);
		puts("");
	}
}
```

运行之后输入 seq.txt 里的内容，就打印出 flag 的图形了。因为横屏不够宽度，所以交换了一下行列，竖屏打印，而且是左右调转的。
$$
flag\{MeowMeow\}
$$
![](https://i.loli.net/2018/10/16/5bc6040610cc4.png)

### 0x3. 她的诗 200

文件是一个 Python 脚本和一段编码过的乱七八糟的文件，运行脚本可以从编码文件中解码出明文，是一首英文诗。根据题目提示，这首诗字面应该是没什么玄机的，要从别的方面下手。（想了半天没有头绪之后）Google 搜索脚本里一段奇怪的字符串 `begin 666`，得知这是 [uuencode 编码](https://en.wikipedia.org/wiki/Uuencoding)，又研究了一下这个编码，好像也没什么玄机（x。最后随便找了个 uudecode 解码网站，把编码文件内容丢进去，咦，解码结果怎么跟脚本解码的不一样？结果多出来的部分拼接在一起就是 flag，剩下两位不全，但可以猜出来。（所以 uuencode 还能隐写，学习了）
$$
flag\{STgAn0grAPhy\_w1tH\_uUeNc0DE\_I5\_50\_fun\}
$$
![](https://i.loli.net/2018/10/17/5bc6a9c031c5d.png)

### 0x4. 她的礼物 250

运行一下给的程序，结果一直在唱~~诗~~歌，歌词是 [The Free Software Song](https://www.gnu.org/music/free-software-song.en.html)。

打开 IDA，把程序拖进去，先看看 `init`（初始化函数，会在 `main` 之前执行）。发现程序用了 `alarm`，一定时间后会自动结束，`nop` 掉。直奔 `main`，大概看了下，先验证命令行参数个数为 2 个，然后进行 233333 次循环，每次循环都打印一遍歌词、响铃、执行 `sub_401540`。循环完后打印上面函数处理过的 Key，再调用 `sub_4019A0` 对 Key 做一大堆变换之后输出 flag。这两个函数的变换十分复杂，差点~~当场去世~~直接放弃。决定先用 signsrch 检查一下是不是什么已知的加密算法，结果给出 RIPEMD-160 和 RIPEMD-128 这两个算法，被 `sub_401540` 使用，但另一个函数的算法没识别出来。那有啥用啊？？？

不过想到题目提示用“她的诗”里的第十行作为参数启动程序，这程序又正好要 2 个参数（另一个是程序名），先传参进去运行试试，还是在唱歌。既然程序循环 233333 次，我倒要看看你循环完了输出什么，把 `sleep`, `puts`, `system`, `printf` 这些费时又没用的函数 `nop` 掉，再用参数运行程序，等了一小会，竟然就打印出 flag 了（...
$$
flag\{HowEVER,\_Somedaj,\_sOMe0NE\_wILl\_FiND\_it.\}
$$
![](https://i.loli.net/2018/10/17/5bc6b15971900.png)