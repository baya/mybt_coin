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

## How to Play

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

```

如果陷入了困境，可以删除矿工，重新开始:

```
$ ./kyk_miner.out delete
```



