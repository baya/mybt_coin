#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <leveldb/c.h>
#include "dbg.h"

int main()
{
    leveldb_t *db;                                                 /* db handler */
    leveldb_options_t *db_opts = leveldb_options_create();         /* 创建 db 相关的 options       */
    leveldb_options_set_create_if_missing(db_opts, 1);             /* 如果数据库不存在则创建一个数据库 */
    char *errptr = NULL;                                           /* 用于存储错误信息的指针, 如果为 NULL 则表示正常    */
    char *db_path = "/tmp/toy_data";                               /* 在 /tmp 路径下设置一个叫 toy_data 的 leveldb 数据库 */
    leveldb_writeoptions_t *write_opts = NULL;                     /* 写操作选项的指针 */
    leveldb_readoptions_t *read_opts = NULL;                       /* 读操作选项的指针 */
    leveldb_writebatch_t* wb = NULL;                               /* 批量写的指针    */
    leveldb_iterator_t *iter = NULL;                               /* 迭代器指针      */
    char *value = NULL;
    size_t vlen = 0;

    db = leveldb_open(db_opts, db_path, &errptr);                  /* 打开一个数据库   */
    check(errptr == NULL, "open db error: %s", errptr);            /* 检查打开或者创建数据库时是否出现错误 */
    write_opts = leveldb_writeoptions_create();                    /* 创建用于写操作的 options */
    char key1[] = {'a', 'b', 'c', '\0'};
    char val1[]  = {'1','2','3','\0'};
    leveldb_put(db, write_opts, key1, sizeof(key1), val1, sizeof(val1), &errptr);      /* 写入 key 为 "abc", value 为 "123" 的数据 */
    check(errptr == NULL, "write error: %s", errptr);

    char key2[] = {'f', 'o', 'o', '\0'};
    char val2[]  = {'b','a','r','\0'};
    leveldb_put(db, write_opts, key2, sizeof(key2), val2, sizeof(val2), &errptr);      /* 写入 key 为 "foo", value 为 "bar" 的数据 */
    check(errptr == NULL, "write error: %s", errptr);

    read_opts = leveldb_readoptions_create();                                 /* 创建用于读操作的 options */
    value = leveldb_get(db, read_opts, key1, sizeof(key1), &vlen, &errptr);   /* 读取 key 为 "abc" 的数据 */
    check(errptr == NULL, "get error: %s", errptr);
    printf("get value: %s from key: %s, value len: %zu\n", value, key1, vlen);

    value = leveldb_get(db, read_opts, key2, sizeof(key2), &vlen, &errptr);   /* 读取 key 为 "abc" 的数据 */
    check(errptr == NULL, "get error: %s", errptr);
    printf("get value: %s from key: %s, value len: %zu\n", value, key2, vlen);

    leveldb_delete(db, write_opts, "abc", 3, &errptr);  /* 删除 key 为 {'a','b','c'} 的 key/value pairs */
    leveldb_delete(db, write_opts, "abc", 4, &errptr);  /* 删除 key 为 {'a','b','c', '\0'} 的 key/value pairs */

    /*
      默认情况下 leveldb 的写操作是异步的，意思是写函数执行完以后，会立即返回而不是等待数据写入到了磁盘中才返回, 这样可以提高 leveldb 的写的性能
      现在我们设定写操作是同步的，这样写函数会等待数据写入到磁盘中以后才返回
     */
    leveldb_writeoptions_set_sync(write_opts, 1);
    
    /*
      创建批量写的容器, 批量写的容器还有 5 对应的种操作方法:
      1. destroy, leveldb_writebatch_destroy, 销毁容器，也就是回收容器所占的内存
      2. clear, leveldb_writebatch_clear, 清空容器里的元素
      3. put, leveldb_writebatch_put, 往容器里加元素，此时数据并没有写到磁盘中
      4. delete, leveldb_writebatch_delete, 删除容器里的某个元素
      5. iterate, leveldb_writebatch_iterate, 遍历容器里的元素
    */
    wb = leveldb_writebatch_create();             

    leveldb_writebatch_put(wb, "foo1", 5, "bar1", 5); /* 往容器 wb 里添加 key 为 "foo1", value 为 "bar1" 的数据 */
    leveldb_writebatch_put(wb, "foo2", 5, "bar2", 5); /* 往容器 wb 里添加 key 为 "foo2", value 为 "bar2" 的数据 */
    leveldb_writebatch_put(wb, "foo3", 5, "bar3", 5); /* 往容器 wb 里添加 key 为 "foo3", value 为 "bar3" 的数据 */
    leveldb_writebatch_put(wb, "foo4", 5, "bar4", 5); /* 往容器 wb 里添加 key 为 "foo4", value 为 "bar4" 的数据 */
    leveldb_writebatch_delete(wb, "foo3", 5);         /* 将 key 为 "foo3" 的元素从容器 wb 里删除掉 */
    leveldb_write(db, write_opts, wb, &errptr);       /* 将容器里的数据写入到磁盘中, 此时容器里没有 key 为 "foo3" 的这条数据 */


    leveldb_readoptions_set_verify_checksums(read_opts, 1); /* 对从文件系统读取的所有数据进行校验和验证, 默认不使用 */
    leveldb_readoptions_set_fill_cache(read_opts, 0);

    iter = leveldb_create_iterator(db, read_opts);         /* 创建迭代器 */
    leveldb_iter_seek_to_first(iter);                      /* 从第一条数据开始遍历 */

    while (leveldb_iter_valid(iter)) {
    	const char *key;
    	const char *val;
    	size_t klen;
    	size_t vlen;

    	key = leveldb_iter_key(iter, &klen);
    	val = leveldb_iter_value(iter, &vlen);

    	printf("key=%s value=%s\n", key, val);

    	leveldb_iter_next(iter);
    }

    leveldb_readoptions_destroy(read_opts);
    leveldb_iter_destroy(iter);
    leveldb_writebatch_destroy(wb);
    leveldb_writeoptions_destroy(write_opts);
    leveldb_options_destroy(db_opts);
    leveldb_close(db);
    return 0;
error:
    if(read_opts) leveldb_readoptions_destroy(read_opts);
    if(iter) leveldb_iter_destroy(iter);
    if(wb) leveldb_writebatch_destroy(wb);
    if(write_opts) leveldb_writeoptions_destroy(write_opts);
    if(db_opts) leveldb_options_destroy(db_opts);
    if(db) leveldb_close(db);
    return -1;
}
