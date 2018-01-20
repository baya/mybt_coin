## Mac OS

安装 leveldb:

```
$ brew install leveldb
```

安装 openssl 库:

```
$ brew install openssl
```

安装 gmp 库:

```
$ brew install gmp
```

## Ubuntu

安装 clang, 目前在 Ubuntu 上只支持 clang 编译器

```
$ sudo apt-get install clang
```

安装 leveldb:

```
$ git clone https://github.com/google/leveldb.git
$ cd leveldb/
$ make
$ sudo scp out-static/lib* out-shared/lib* /usr/local/lib/
$ cd include/
$ sudo scp -r leveldb /usr/local/include/
$ sudo ldconfig

```

安装 openssl 库:

```
$ sudo apt-get install libssl-dev
```

安装 gmp 库:

```
$ sudo apt-get install libgmp3-dev
```

## 矿工节点

```
$ git clone https://github.com/baya/mybt_coin.git

$ cd /path/to/mybt_coin

$ make

$ make kyk_miner

$ ./kyk_miner.out             # 查看支持的命令

$ ./kyk_miner.out init        # 初始化矿工

$ ./kyk_miner.out makeBlock   # 生产一个区块, 这个区块包含 100 BTC, 并且只包含一笔 coinbase 交易, 即矿工给自己增加 100 个BTC, 真实的 BTC 网络在后期是不允许这样操作的

输出: maked a new block: 0000f5e6d8700e78989ac97ac12a0c6f216e5ad42a7008ec22298f1d997abe63

$ ./kyk_miner.out queryBlance # 查询拥有的 BTC 数量
输出: 100.000000 BTC

$ ./kyk_miner.out queryBlock 0000f5e6d8700e78989ac97ac12a0c6f216e5ad42a7008ec22298f1d997abe63  # 查询 block 数据

输出:
wVersion: 1
nHeight:  0
nStatus:  24
nTx:      1
nFile:    0
nDataPos: 242
nUndoPos: 0
Following is Block Header:
nVersion: 1
PrevHash : 0000876c9ef8c1f8b2a3012ec1bdea7296f95ae21681799f8adf967f548bf8f3
hashMerkleRoot : 0b527174947e9d808c3d4d2dbf1780be764a53ce22fbc09d124f0e4a02686d43
nTime:    1514128378
nBits:    1f00ffff
nNonce:   64368

$ ./kyk_miner.out makeTx 8 invalidaddress                     # 向非法地址转账失败

$ ./kyk_miner.out makeTx 8 1KAWPAD8KovUo53pqHUY2bLNMTYa1obFX9 # 向正常的地址转账成功

$ ./kyk_miner.out queryBalance                                # 查询余额, 因为每当生成一笔交易时，矿工都会创建一个新的 block, 这样矿工会转出 8 BTC 同时增加 100 BTC, 无矿工费用, 矿工费用可以在 src/kyk_defs.h 文件中设置

输出:
192.000000 BTC

$ ./kyk_miner.out addAddress "a2"                             # 增加一个 label 为 "a2" 的地址

输出:
Added a new address: 13dqX7yNia35V2dZkM5dMyTExocyPTAbAT

$ ./kyk_miner.out showAddrList                                # 显示矿工当前拥有的地址

输出:
1GkfyvQod8Bj4nFTrTejdr64kMprqTFSgb
13dqX7yNia35V2dZkM5dMyTExocyPTAbAT

$ ./kyk_miner.out makeTx 9 13dqX7yNia35V2dZkM5dMyTExocyPTAbAT  # 矿工给自己控制的地址发送 9 个比特币, 结果是增加 100 个比特币

./kyk_miner.out queryBalance                          

输出:
292.000000 BTC


$ ./kyk_miner.out serve 8333                                  # 启动服务

```

如果陷入了困境，可以删除矿工，重新开始:

```
$ ./kyk_miner.out delete
```


## 钱包和矿工节点的交互

首先我们将前面的矿工节点删除:

```
$ ./kyk_miner.out delete
```

初始化矿工节点:

```
$ ./kyk_miner.out init
```

预挖矿:

```
$ ./kyk_miner.out makeBlock
```

查询矿工节点拥有的比特币数量, 此时矿工节点拥有 100 个比特币, 我在程序中设定的是每出一个块, 将产生 100 个比特币.

```
$ ./kyk_miner.out queryBalance

100.000000 BTC
```

构建 Bob wallet, Bob wallet 是一个 spv钱包，简单理解就是一个轻量级的客户端，这种客户端不能进行挖矿操作.

```
$ make bob_wallet
```

初始化 Bob wallet:

```
$ ./bob_wallet.out init
```

查询 Bob wallet 的余额, 此时 Bob wallet 的比特币数量为 0

```
$ ./bob_wallet.out queryBalance

0.000000 BTC
```

显示 Bob wallet 的用于接收比特币的地址:

```
$ ./bob_wallet.out showAddrList

168wfy7TCmyEgQncK9rYRCjn8QE1zmK8cA
```

在此次交互实验中, Bob wallet 的比特币地址是 168wfy7TCmyEgQncK9rYRCjn8QE1zmK8cA, 请用你实际得到的地址替换这个地址.


因为 Bob wallet 没有挖矿的功能, 它只能通过其他人给它发送比特币的方式获得比特币, 现在我们的矿工节点会给 Bob wallet 发送 10 个比特币


```
$ ./kyk_miner.out makeTx 10 168wfy7TCmyEgQncK9rYRCjn8QE1zmK8cA
```

此时 Bob wallet 已经有了 10 比特币了，但是 Bob wallet 并不知道它已经拥有了 10 个比特币, 只有从矿工节点同步数据后它才能知道自己拥有了 10 个比特币.

启动矿工节点的服务:

```
$ ./kyk_miner.out serve
```

Bob wallet 测试和矿工节点的连接:

```
$ ./bob_wallet.out ping
```

Bob wallet 从矿工节点同步区块头数据:

```
$ ./bob_wallet.out req-getheaders
```

Bob wallet 从矿工节点同步数据:

```
$ ./bob_wallet.out req-getdata
```

此时 Bob wallet 知道它拥有了 10 个比特币:

```
$ ./bob_wallet.out queryBalance

10.000000 BTC
```

构建 Alice wallet, Alice wallet 是一个和 Bob wallet 功能一致的 spv wallet, 唯一的区别就是名字不一样.

```
$ make alice_wallet
```

初始化 Alice wallet:

```
$ ./alice_wallet.out init
```

查询 Alice wallet 拥有的比特币数量, 此时 Alice wallet 拥有的比特币数量为 0.

```
$ ./alice_wallet.out queryBalance

0.000000 BTC
```

显示 Alice wallet 用于接收比特币的地址

```
$ ./alice_wallet.out showAddrList

1YYxf8n2jJszrEMkqd9HirGDuAF5Z8fEQ
```

请使用你实际得到的比特币地址替换地址 `1YYxf8n2jJszrEMkqd9HirGDuAF5Z8fEQ`.


Bob wallet 向 Alice wallet 发送 3 个比特币:

```
$ ./bob_wallet.out makeTx 3 1YYxf8n2jJszrEMkqd9HirGDuAF5Z8fEQ
```

Bob wallet 从矿工节点同步数据后, Bob wallet 将确认自己的余额:

```
$ ./bob_wallet.out req-getheaders

$ ./bob_wallet.out req-getdata

$ ./bob_wallet.out queryBalance

6.999000 BTC
```

Bob wallet 此时余额为 6.999000 BTC, 其中 0.001 个比特币作为矿工费支付给了矿工.


Alice wallet 从矿工节点那同步数据后, Alice wallet 将知道它已经拥有了 3 个比特币.


```
$ ./alice_wallet.out req-getheaders

$ ./alice_wallet.out req-getdata

$ ./alice_wallet.out queryBalance

3.000000 BTC
```

此时 Alice wallet 拥有 3 个比特币.


## 重新开始实验

```
$ ./kyk_miner.out delete

$ ./bob_wallet.out delete

$ ./alice_wallet.out delete
```

## 补充阅读

[区块链技术探索(一), 构造比特币的创世区块](http://baya.github.io/2017/05/11/7daystalk.html)

[区块链技术探索(二), 打造我们自己的比特币](http://baya.github.io/2017/09/04/build-our-btc-system.html)
