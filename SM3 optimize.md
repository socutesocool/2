### SM3的实现与优化

##### 消息填充

SM3的消息扩展步骤是以512位的数据分组作为输入的。因此需要在一开始就把数据长度填充至512位的倍数。具体步骤为：

1、先填充一个“1”，后面加上k个“0”。其中k是满足(l+1+k) mod 512 = 448的最小正整数。

2、追加64位的数据长度（bit为单位，大端序存放。）

<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220731023842082.png" alt="image-20220731023842082" style="zoom:80%;" />

##### 迭代压缩

将填充后的消息m'按512b进行分组：$m'=B^{0}B^{1}...B^{n-1}$,其中$n=(l+k+65)/512$.对m'以如下方式迭代：

```c
FOR i=0 TO(n-1)
    V(i+1)=CF(V(i),B(i));
ENDFOR
```

其中，CF是压缩函数，V(0)为256b初始值IV，B(i)为填充后的消息分组，迭代压缩的结果为V(n)。

<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220731023821405.png" alt="image-20220731023821405" style="zoom: 80%;" />

##### 压缩函数

令A,B,C,D,E,F,G,H为字寄存器，SS1,SS2,TT1,TT2为中间变量，压缩函数$V^{(i+1)}=CF(V^{(i)},B^{(i)}),0≤i≤n-1$.计算过程描述如下：

```c
ABCDEFGH←V(i)
FOR j=0 TO 63
    SS1←((A<<<12)+E+(T_j<<<(jmod32)))<<<7
    SS2←SS1⊕(A<<<12)
    TT1←FF_j(A,B,C)+D+SS2+W_j'
    TT2←GG_j(E,F,G)+H+SS1+W_j
    D←C
    C←B<<<9
    B←A
    A←TT1
    H←G
    G←F<<<19
    F←E
    E←P0(TT2)
ENDFOR
V(i+1)←ABCDEFGH⊕V(n)
```

杂凑值

$ABCDEFGH←V^{(n)}$

<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220731024001092.png" alt="image-20220731024001092" style="zoom:80%;" />

优化：

1.用array数组作为中间值，可以减少bytes、list、int之间的类型转换从而达到减小运行时间的效果。

2.调整循环移位运算，pysmx为“一次取模、一次乘法、一次加法”，调整后为“两次移位、一次按位或”，由于位运算比乘除法快，所以运行时间可以减小。

3.由于代码中有大量循环，可以进行并行运算充分利用资源。

运行结果：

<img src="C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20220731025416516.png" alt="image-20220731025416516" style="zoom:80%;" />



参考：https://blog.csdn.net/qq_43339242/article/details/123709822