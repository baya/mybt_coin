#include <iostream>
#include <cassert>
#include <leveldb/db.h>

int main()
{
    std::string db_path = "/Users/jim/workspace/bitcoin-block-data/blocks";
    leveldb::DB* db;
    leveldb::Options options;
    options.create_if_missing = true;
    leveldb::Status status = leveldb::DB::Open(options, db_path, &db);
    assert(status.ok());
    std::cout<< status.ok() <<std::endl;
}
