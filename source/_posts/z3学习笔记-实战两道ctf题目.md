---
title: z3学习笔记---实战两道ctf题目
tags:
  - z3
  - ctf
  - 逆向
date: 2019-09-16 18:35:12
---


#  简介
在两次遇到需要用z3来线性求解的题目，而且两个题目当时都没做出来，第一道是TokyoWesterns CTF easy_crack_me，第二道是护网杯re_quiz_middle
> 1、2019 TokyoWesterns CTF -> easy_crack_me
> 2、2019 护网杯 re_quiz_middle
# easy_crack_me
下面是ida f5查看的结果，简单的校验如下
> 1、检查输入的字符串长度是否为39
> 2、是否以"TWCTF{"开头，以"}"结尾
> 3、统计中间字符串0-9a-f字符的个数并进行比较
> 4、4位为一组，相加得到v21数组，异或得到v25数组和dword_400F40、dword_400F60进行比较
> 5、每隔8位，4个相加得到v29数组，4个异或得到v33数组和dword_400FA0、dword_400F80进行比较
> 6、当前字符为0-9表示为0xff，a-f表示为0x80和dword_400FC0进行比较
> 7、每隔两个相加等于1160
> 8、s[7]=='f' s[11]=='9' s[12]=='7' s[23]='2' s[31]=='4' s[37]=='5'


``` c++
signed __int64 __fastcall main(int a1, char **a2, char **a3)
{
  signed __int64 result; // rax
  char *j; // rax
  char v5; // ST1F_1
  char v6; // ST1E_1
  char v7; // [rsp+1Dh] [rbp-1B3h]
  signed int i; // [rsp+20h] [rbp-1B0h]
  signed int k; // [rsp+24h] [rbp-1ACh]
  int v10; // [rsp+28h] [rbp-1A8h]
  int v11; // [rsp+2Ch] [rbp-1A4h]
  signed int l; // [rsp+30h] [rbp-1A0h]
  signed int m; // [rsp+34h] [rbp-19Ch]
  int v14; // [rsp+38h] [rbp-198h]
  int v15; // [rsp+3Ch] [rbp-194h]
  signed int n; // [rsp+40h] [rbp-190h]
  signed int ii; // [rsp+44h] [rbp-18Ch]
  int v18; // [rsp+48h] [rbp-188h]
  signed int jj; // [rsp+4Ch] [rbp-184h]
  char *s; // [rsp+58h] [rbp-178h]
  __int64 v21; // [rsp+70h] [rbp-160h]
  __int64 v22; // [rsp+78h] [rbp-158h]
  __int64 v23; // [rsp+80h] [rbp-150h]
  __int64 v24; // [rsp+88h] [rbp-148h]
  __int64 v25; // [rsp+90h] [rbp-140h]
  __int64 v26; // [rsp+98h] [rbp-138h]
  __int64 v27; // [rsp+A0h] [rbp-130h]
  __int64 v28; // [rsp+A8h] [rbp-128h]
  __int64 v29; // [rsp+B0h] [rbp-120h]
  __int64 v30; // [rsp+B8h] [rbp-118h]
  __int64 v31; // [rsp+C0h] [rbp-110h]
  __int64 v32; // [rsp+C8h] [rbp-108h]
  __int64 v33; // [rsp+D0h] [rbp-100h]
  __int64 v34; // [rsp+D8h] [rbp-F8h]
  __int64 v35; // [rsp+E0h] [rbp-F0h]
  __int64 v36; // [rsp+E8h] [rbp-E8h]
  __int64 s1; // [rsp+F0h] [rbp-E0h]
  __int64 v38; // [rsp+F8h] [rbp-D8h]
  __int64 v39; // [rsp+100h] [rbp-D0h]
  __int64 v40; // [rsp+108h] [rbp-C8h]
  __int64 v41; // [rsp+110h] [rbp-C0h]
  __int64 v42; // [rsp+118h] [rbp-B8h]
  __int64 v43; // [rsp+120h] [rbp-B0h]
  __int64 v44; // [rsp+128h] [rbp-A8h]
  int v45[32]; // [rsp+130h] [rbp-A0h]
  __int64 v46; // [rsp+1B0h] [rbp-20h]
  __int64 v47; // [rsp+1B8h] [rbp-18h]
  unsigned __int64 v48; // [rsp+1C8h] [rbp-8h]

  v48 = __readfsqword(0x28u);
  if ( a1 == 2 )
  {
    s = a2[1];
    if ( strlen(a2[1]) != 39 )                  // 长度39
    {
      puts("incorrect");
      exit(0);
    }
    if ( memcmp(s, "TWCTF{", 6uLL) || s[38] != '}' )// 内容32
    {
      puts("incorrect");
      exit(0);
    }
    s1 = 0LL;
    v38 = 0LL;
    v39 = 0LL;
    v40 = 0LL;
    v41 = 0LL;
    v42 = 0LL;
    v43 = 0LL;
    v44 = 0LL;
    v46 = 0x3736353433323130LL;
    v47 = 0x6665646362613938LL;                 // 0-9a-f
    for ( i = 0; i <= 15; ++i )
    {
      for ( j = strchr(s, *((char *)&v46 + i)); j; j = strchr(j + 1, *((char *)&v46 + i)) )// 把0-9a-f进行计数
        ++*((_DWORD *)&s1 + i);
    }
    if ( memcmp(&s1, &dword_400F00, 0x40uLL) )  // 计数进行比较
                                                // 0:3 1:2 2:2 3:0 4:3 5:2 6:1 7:3 
                                                // 8:3 9:1 a:1 b:3 c:1 d:2 e:2 f:3
    {
      puts("incorrect");
      exit(0);
    }
    v21 = 0LL;
    v22 = 0LL;
    v23 = 0LL;
    v24 = 0LL;
    v25 = 0LL;
    v26 = 0LL;
    v27 = 0LL;
    v28 = 0LL;
    for ( k = 0; k <= 7; ++k )                  // 4位为一组，相加得到v21数组，异或得到v25数组
    {
      v10 = 0;
      v11 = 0;
      for ( l = 0; l <= 3; ++l )
      {
        v5 = s[4 * k + 6 + l];
        v10 += v5;
        v11 ^= v5;
      }
      *((_DWORD *)&v21 + k) = v10;
      *((_DWORD *)&v25 + k) = v11;
    }
    v29 = 0LL;
    v30 = 0LL;
    v31 = 0LL;
    v32 = 0LL;
    v33 = 0LL;
    v34 = 0LL;
    v35 = 0LL;
    v36 = 0LL;
    for ( m = 0; m <= 7; ++m )                  // 每隔8位，4个相加得到v29数组，4个异或得到v33数组
    {
      v14 = 0;
      v15 = 0;
      for ( n = 0; n <= 3; ++n )
      {
        v6 = s[8 * n + 6 + m];
        v14 += v6;
        v15 ^= v6;
      }
      *((_DWORD *)&v29 + m) = v14;
      *((_DWORD *)&v33 + m) = v15;
    }
    if ( memcmp(&v21, &dword_400F40, 0x20uLL) || memcmp(&v25, &dword_400F60, 0x20uLL) )
    {
      puts("incorrect");
      exit(0);
    }
    if ( memcmp(&v29, &dword_400FA0, 0x20uLL) || memcmp(&v33, &dword_400F80, 0x20uLL) )
    {
      puts("incorrect");
      exit(0);
    }
    memset(v45, 0, sizeof(v45));
    for ( ii = 0; ii <= 31; ++ii )              // 47<v7<=57 255
                                                // 96<v7<=102 128
                                                // 其他 0
    {
      v7 = s[ii + 6];
      if ( v7 <= 47 || v7 > 57 )
      {
        if ( v7 <= 96 || v7 > 102 )
          v45[ii] = 0;
        else
          v45[ii] = 128;
      }
      else
      {
        v45[ii] = 255;
      }
    }
    if ( memcmp(v45, &dword_400FC0, 0x80uLL) )
    {
      puts("incorrect");
      exit(0);
    }
    v18 = 0;
    for ( jj = 0; jj <= 15; ++jj )              // 每隔两个相加得1160
      v18 += s[2 * (jj + 3)];
    if ( v18 != 1160 )
    {
      puts("incorrect");
      exit(0);
    }
    if ( s[37] != '5' || s[7] != 'f' || s[11] != '8' || s[12] != '7' || s[23] != '2' || s[31] != '4' )
    {
      puts("incorrect");
      exit(0);
    }
    printf("Correct: %s\n", s, a2);
    result = 0LL;
  }
  else
  {
    fwrite("./bin flag_is_here", 1uLL, 0x12uLL, stderr);
    result = 1LL;
  }
  return result;
}
```
这个题目还是比较简单的，有很多位已经直接给出了，按上面的分析写出约束条件很快就能跑出答案TWCTF{df2b4877e71bd91c02f8ef6004b584a5}。
题解代码如下

``` python
# coding:utf-8
from z3 import *
import time

# 参考
t1 = time.time()

# 创建一个解决方案案例
solver = Solver()

# flag长度设置为39
a = [BitVec('flag%d' % i, 8) for i in range(39)]
# 设置flag格式
for i in range(6):
    solver.add(a[i] == ord('TWCTF{'[i]))

solver.add(a[38] == ord('}'))
# 0-9a-f统计校验 0x30-0x39 0x61-0x66
# true_num = [3, 2, 2, 0, 3, 2, 1, 3, 3, 1, 1, 3, 1, 2, 2, 3]
solver.add(sum([If(i == ord('0'), 1, 0) for i in a]) == 3)
solver.add(sum([If(i == ord('1'), 1, 0) for i in a]) == 2)
solver.add(sum([If(i == ord('2'), 1, 0) for i in a]) == 2)
solver.add(sum([If(i == ord('3'), 1, 0) for i in a]) == 0)
solver.add(sum([If(i == ord('4'), 1, 0) for i in a]) == 3)
solver.add(sum([If(i == ord('5'), 1, 0) for i in a]) == 2)
solver.add(sum([If(i == ord('6'), 1, 0) for i in a]) == 1)
solver.add(sum([If(i == ord('7'), 1, 0) for i in a]) == 3)
solver.add(sum([If(i == ord('8'), 1, 0) for i in a]) == 3)
solver.add(sum([If(i == ord('9'), 1, 0) for i in a]) == 1)
solver.add(sum([If(i == ord('a'), 1, 0) for i in a]) == 1)
solver.add(sum([If(i == ord('b'), 1, 0) for i in a]) == 3)
solver.add(sum([If(i == ord('c'), 1, 0) for i in a]) == 1)
solver.add(sum([If(i == ord('d'), 1, 0) for i in a]) == 2)
solver.add(sum([If(i == ord('e'), 1, 0) for i in a]) == 2)
solver.add(sum([If(i == ord('f'), 1, 0) for i in a]) == 3)
#############################################################################################
#  4位为一组，相加得到v21数组，异或得到v25数组
# v21_true = [0x15e, 0xda, 0x12f, 0x131, 0x100, 0x131, 0xfb, 0x102]
# v25_true = [0x52, 0xc, 0x1, 0xf, 0x5c, 0x5, 0x53, 0x58]
solver.add(a[6] + a[7] + a[8] + a[9] == 0x15e,
           a[10] + a[11] + a[12] + a[13] == 0xda)
solver.add(a[14] + a[15] + a[16] + a[17] == 0x12f,
           a[18] + a[19] + a[20] + a[21] == 0x131)
solver.add(a[22] + a[23] + a[24] + a[25] == 0x100,
           a[26] + a[27] + a[28] + a[29] == 0x131)
solver.add(a[30] + a[31] + a[32] + a[33] == 0xfb,
           a[34] + a[35] + a[36] + a[37] == 0x102)

solver.add(a[6] ^ a[7] ^ a[8] ^ a[9] == 0x52,
           a[10] ^ a[11] ^ a[12] ^ a[13] == 0xc)
solver.add(a[14] ^ a[15] ^ a[16] ^ a[17] == 0x1,
           a[18] ^ a[19] ^ a[20] ^ a[21] == 0xf)
solver.add(a[22] ^ a[23] ^ a[24] ^ a[25] == 0x5c,
           a[26] ^ a[27] ^ a[28] ^ a[29] == 0x5)
solver.add(a[30] ^ a[31] ^ a[32] ^ a[33] == 0x53,
           a[34] ^ a[35] ^ a[36] ^ a[37] == 0x58)
#############################################################################################
# v29_true = [0x129, 0x103, 0x12b, 0x131, 0x135, 0x10b, 0xff, 0xff]
# v33_true = [0x1, 0x57, 0x7, 0xd, 0xd, 0x53, 0x51, 0x51]
solver.add(a[6] + a[14] + a[22] + a[30] == 0x129,
           a[7] + a[15] + a[23] + a[31] == 0x103)
solver.add(a[8] + a[16] + a[24] + a[32] == 0x12b,
           a[9] + a[17] + a[25] + a[33] == 0x131)
solver.add(a[10] + a[18] + a[26] + a[34] == 0x135,
           a[11] + a[19] + a[27] + a[35] == 0x10b)
solver.add(a[12] + a[20] + a[28] + a[36] == 0xff,
           a[13] + a[21] + a[29] + a[37] == 0xff)

solver.add(a[6] ^ a[14] ^ a[22] ^ a[30] ^ 0 == 0x1,
           a[7] ^ a[15] ^ a[23] ^ a[31] ^ 0 == 0x57)
solver.add(a[8] ^ a[16] ^ a[24] ^ a[32] ^ 0 == 0x7,
           a[9] ^ a[17] ^ a[25] ^ a[33] ^ 0 == 0xd)
solver.add(a[10] ^ a[18] ^ a[26] ^ a[34] ^ 0 == 0xd,
           a[11] ^ a[19] ^ a[27] ^ a[35] ^ 0 == 0x53)
solver.add(a[12] ^ a[20] ^ a[28] ^ a[36] ^ 0 == 0x51,
           a[13] ^ a[21] ^ a[29] ^ a[37] ^ 0 == 0x51)
#############################################################################################
# ff '0'<= <='9'
# 80 'a'<= <='f'
# v45_true = [0x80, 0x80, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF,
#             0x80, 0xFF, 0xFF, 0x80, 0x80, 0xFF, 0xFF, 0x80,
#             0xFF, 0xFF, 0x80, 0xFF, 0x80, 0x80, 0xFF, 0xFF,
#             0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0x80, 0xFF]

# 0x80, 0x80, 0xFF, 0x80
solver.add(ord('a') <= a[6], a[6] <= ord('f'),  # 0x80 'a'<= <='f'
           ord('a') <= a[7], a[7] <= ord('f'),  # 0x80 'a'<= <='f'
           ord('0') <= a[8], a[8] <= ord('9'),
           ord('a') <= a[9], a[9] <= ord('f'))  # 0x80 'a'<= <='f'
# 0xFF, 0xFF, 0xFF, 0xFF
solver.add(ord('0') <= a[10], a[10] <= ord('9'),
           ord('0') <= a[11], a[11] <= ord('9'),
           ord('0') <= a[12], a[12] <= ord('9'),
           ord('0') <= a[13], a[13] <= ord('9'))
# 0x80, 0xFF, 0xFF, 0x80
solver.add(ord('a') <= a[14], a[14] <= ord('f'),  # 0x80 'a'<= <='f'
           ord('0') <= a[15], a[15] <= ord('9'),
           ord('0') <= a[16], a[16] <= ord('9'),
           ord('a') <= a[17], a[17] <= ord('f'))  # 0x80 'a'<= <='f'
# 0x80, 0xFF, 0xFF, 0x80
solver.add(ord('a') <= a[18], a[18] <= ord('f'),  # 0x80 'a'<= <='f'
           ord('0') <= a[19], a[19] <= ord('9'),
           ord('0') <= a[20], a[20] <= ord('9'),
           ord('a') <= a[21], a[21] <= ord('f'))  # 0x80 'a'<= <='f'
# 0xFF, 0xFF, 0x80, 0xFF
solver.add(ord('0') <= a[22], a[22] <= ord('9'),
           ord('0') <= a[23], a[23] <= ord('9'),
           ord('a') <= a[24], a[24] <= ord('f'),  # 0x80 'a'<= <='f'
           ord('0') <= a[25], a[25] <= ord('9'))
# 0x80, 0x80, 0xFF, 0xFF
solver.add(ord('a') <= a[26], a[26] <= ord('f'),  # 0x80 'a'<= <='f'
           ord('a') <= a[27], a[27] <= ord('f'),  # 0x80 'a'<= <='f'
           ord('0') <= a[28], a[28] <= ord('9'),
           ord('0') <= a[29], a[29] <= ord('9'))
# 0xFF, 0xFF, 0x80, 0xFF
solver.add(ord('0') <= a[30], a[30] <= ord('9'),
           ord('0') <= a[31], a[31] <= ord('9'),
           ord('a') <= a[32], a[32] <= ord('f'),  # 0x80 'a'<= <='f'
           ord('0') <= a[33], a[33] <= ord('9'))
# 0xFF, 0xFF, 0x80, 0xFF
solver.add(ord('0') <= a[34], a[34] <= ord('9'),
           ord('0') <= a[35], a[35] <= ord('9'),
           ord('a') <= a[36], a[36] <= ord('f'),  # 0x80 'a'<= <='f'
           ord('0') <= a[37], a[37] <= ord('9'))
#############################################################################################
# 求和比较
solver.add(
    a[6] + a[8] + a[10] + a[12] + a[14] + a[16] + a[18] + a[20] + a[22] + a[24] + a[26] + a[28] + a[30] + a[32] +
    a[34] + a[36] == 1160)
#############################################################################################
solver.add(a[37] == ord('5'))
solver.add(a[7] == ord('f'))
solver.add(a[11] == ord('8'))
solver.add(a[12] == ord('7'))
solver.add(a[23] == ord('2'))
solver.add(a[31] == ord('4'))

print(solver.check())
if solver.check() == sat:
    m = solver.model()
    flag = "".join([chr(m[each].as_long()) for each in a])
    print(flag)
else:
    print('error')

t2 = time.time()
print(t2 - t1)

```
# re_quiz_middle
其实这道题分析也很简单，但是当时对z3不是很了解所以代码写不出来是真的难受

>1、检查输入字符串长度是否为21
>2、检查字符串格式是否为flag{***************}
>3、用内容最后的三位做种子循环生成种子数组c[12]
>4、根据种子的比特位决定是相加还是异或得到d[12]
>5、d[12]与v30到v41的12个数组进行比较

思路挺简单的，下面是代码，我的渣渣笔记本大概要1个小时才能出答案，室友大概跑了20分钟出答案flag{Sylb11ic_2funny}

``` python
# coding:utf-8
from z3 import *
import time

# 参考 https://rise4fun.com/z3/tutorialcontent/guide
# https://anee.me/solving-a-simple-crackme-using-z3-68c55af7f7b1
t1 = time.time()

# 创建一个解决方案案例
solver = Solver()
# flag{0123456789abcde}
# 012345678901234567890
# flag长度设置为21
a = [BitVec('a%d' % i, 32) for i in range(21)]
b = [BitVec('b%d' % i, 32) for i in range(13)]
c = [BitVec('c%d' % i, 32) for i in range(13)]
d = [BitVec('d%d' % i, 32) for i in range(12)]

# 设置flag格式
for i in range(5):
    solver.add(a[i] == ord('flag{'[i]))
for i in range(21):
    solver.add(a[i] >= 0x20, a[i] <= 0x7f)
for i in range(12):
    d[i] = 0
solver.add(a[20] == ord('}'))
check = [0x21A, 0x110, 0x106, 0x16A, 0x3E4, 0x23A, 0x2E2, 0x13E, 0x2DE, 0x1FE, 0x34A, 0x1E8]
b[0] = (a[19] << 16) + (a[18] << 8) + a[17]
c[0] = b[0]
for i in range(1, 13):
    b[i] = 0x343FD * b[i - 1] + 0x269EC3
    c[i] = (b[i] >> 16) & 0x7FFF


for i in range(12):
    for j in range(12):
        d[i] = If((((c[i+1] >> j) & 0x1) == 0x1), d[i] + a[5 + j], d[i] ^ a[5 + j])
    solver.add(d[i] == check[i])

if solver.check() == sat:
    m = solver.model()
    flag = "".join([chr(m[each].as_long()) for each in a])
    print(flag)
else:
    print('error')

t2 = time.time()
print(t2 - t1)

```

# 链接
[z3库教程](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
[本文的样例和代码百度云链接](https://pan.baidu.com/s/1iGcBxku2NtjMggzTxF2_VA)