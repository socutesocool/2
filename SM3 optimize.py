import time,os,math,random,re,sys,multiprocessing
from pysmx.SM3 import digest as SM3_pysmx
from gmssl.sm3 import sm3_hash
from array import array
from typing import Counter
from functools import reduce

Tj_rl = array('L', ((0x79cc4519 << j | 0x79cc4519 >> 32-j) & 0xffffffff for j in range(16)))#确保是32位
Tj_rl.extend((0x7a879d8a << (j & 31) | 0x7a879d8a >> (32 - j & 31)) & 0xffffffff for j in range(16, 64))
V0 = array('L', [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e])
 

#CF为压缩函数
def CF(V, B):
    #将消息分组B按以下方法扩展生成132个消息字W0,W1,...W63
    W = array('L', B)
    for j in range(16, 68):
        X = W[j-16] ^ W[j-9] ^ (W[j-3] << 15 | W[j-3] >> 17) & 0xffffffff
        W.append((X ^ (X << 15 | X >> 17) ^ (X << 23 | X >> 9) ^ (W[j-13] << 7 | W[j-13] >> 25) ^ W[j-6]) & 0xffffffff)
    W_ = array('L', (W[j] ^ W[j+4] for j in range(64)))
    #A-H为字寄存器
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        A_rl12 = A << 12 | A >> 20
        tmp = (A_rl12 + E + Tj_rl[j]) & 0xffffffff
        SS1 = (tmp << 7 | tmp >> 25)
        SS2 = SS1 ^ A_rl12
        if j & 0x30:
            FF, GG = A & B | A & C | B & C, E & F | ~E & G
        else:
            FF, GG = A ^ B ^ C, E ^ F ^ G
        TT1, TT2 = (FF + D + SS2 + W_[j]) & 0xffffffff, (GG + H + SS1 + W[j]) & 0xffffffff
        C = (B << 9 | B >> 23) & 0xffffffff
        D = C
        G = (F << 19 | F >> 13) & 0xffffffff
        H = G
        A = TT1
        B = A
        E = (TT2 ^ (TT2 << 9 | TT2 >> 23) ^ (TT2 << 17 | TT2 >> 15)) & 0xffffffff
        F = E
    return A ^ V[0], B ^ V[1], C ^ V[2], D ^ V[3], E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]
 
 
def digest(data):
    #填充
    num = 64 - (len(data) + 1 & 0x3f)
    data += b'\x80' + (len(data) << 3).to_bytes(num if num >= 8 else num + 64, 'big')
    V = V0
    B = array('L',data)
    B.byteswap()
    #迭代压缩
    for i in range(0, len(B), 16):
        V = CF(V, B[i:i+16])
    V = array('L', V)
    V.byteswap()
    return V.tobytes()
 
def SM3_gmssl(data: bytes) -> bytes:
    return bytes.fromhex(sm3_hash([i for i in data]))
 
 
def SM3_youhua(data: bytes) -> bytes:
    return digest(data)
 
 
def sm3():
    n = 100  # 测试次数
    # 随机生成消息
    short_data = [os.urandom(50) for i in range(n)]  # 短消息列表
    long_data = [os.urandom(1000) for i in range(n)]  # 长消息列表
    hash_data = n*[b'']
    hash_data1 = n*[b'']
    hash_data2 = n*[b'']
    hash_data3 = n*[b'']
    hash_data4 = n*[b'']
 
    print('短消息长度：%dB  长消息长度：%dB  测试次数：%d' % (len(short_data[0]), len(long_data[0]), n))
    print('\t\t\t短消息Hash\t长消息Hash')
 
    #gmssl
    time1 = time.time()
    for i in range(n):
        hash_data1[i] = SM3_gmssl(short_data[i])
    time2 = time.time()
    for i in range(n):
        hash_data2[i] = SM3_gmssl(long_data[i])
    time3 = time.time()
    print('gmssl-SM3\t\t%.1f\t\t%.1f' % ((time2 - time1) * 1000, (time3 - time2) * 1000))
    time_A = time3 - time1
 
    #pysmx
    time1 = time.time()
    for i in range(n):
        hash_data3[i] = SM3_pysmx(short_data[i])
    time2 = time.time()                              
    for i in range(n):
        hash_data4[i] = SM3_pysmx(long_data[i])
    time3 = time.time()
    print('pysmx-SM3\t\t%.1f\t\t%.1f' % ((time2 - time1) * 1000, (time3 - time2) * 1000))
    time_B = time3 - time1
    assert hash_data1 == hash_data3 and hash_data2 == hash_data4
 
    #youhua
    time1 = time.time()
    for i in range(n):
        hash_data1[i] = SM3_youhua(short_data[i])
    time2 = time.time()
    for i in range(n):
        hash_data2[i] = SM3_youhua(long_data[i])
    time3 = time.time()
    print('youhua-SM3\t\t%.1f\t\t%.1f' % ((time2 - time1) * 1000, (time3 - time2) * 1000))
    time_youhua = time3 - time1
    print('优化后总耗时为pysmx的%.1f%%、gmssl的%.1f%%' % (time_youhua / time_B * 100, time_youhua / time_A * 100))

sm3()
