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
$ cd /path/to/mybt_coin

$ make

$ make kyk_miner

$ ./kyk_miner.out init

$ ./kyk_miner.out             # 查看相关的命令

$ ./kyk_miner.out init

$ ./kyk_miner.out makeBlock   # 生产一个区块, 这个区块包含 100 BTC

$ ./kyk_miner.out queryBlance # 查询拥有的 BTC 数量

```



