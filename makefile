OPTLIBS = -lcrypto -lgmp
LIB_PATHS = /usr/local/opt/openssl/lib
INC_PATHS = /usr/local/opt/openssl/include
CFLAGS = -g -O2 -Wall -Wextra -Isrc -I$(INC_PATHS) -DNDEBUG $(OPTFLAGS)
LIBS = -ldl $(OPTLIBS)
PREFIX ?= /usr/local

SOURCES = $(wildcard src/**/*.c src/*.c)
OBJECTS = $(patsubst %.c, %.o, $(SOURCES))

TEST_SRC = $(wildcard tests/*_tests.c)
TESTS = $(patsubst %.c, %.out, $(TEST_SRC))

TARGET = build/libMY_LIBARAY.a
SO_TARGET = $(patsubst %.a, %.so, $(TARGET))

# The Target Build
all: $(TARGET) $(SO_TARGET) tests

dev: CFLAGS = -g -Wall -Isrc -Wextra -Wextra $(OPTFLAGS)
dev: all

$(TARGET): CFLAGS += -fPIC

# 运行实际创建`TARGET`的`ar`的命令。`$@ $(OBJECTS)`语法的意思是，将当前目标的名称放在这里，并把`OBJECTS`的内容放在后面。这里`$@`的值为19行的`$(TARGET)`，
# 它实际上为`build/libMY_LIBRARY.a`。看起来在这一重定向中它做了很多跟踪工作，它也有这个功能，并且你可以通过修改顶部的`TARGET`，来构建一个全新的库。
$(TARGET): build $(OBJECTS)
	ar rcs $@ $(OBJECTS)
	ranlib $@

$(SO_TARGET): $(TARGET) $(OBJECTS)
	$(CC) -shared -o $@ $(OBJECTS) -L$(LIB_PATHS) $(LIBS)


build:
	@mkdir -p build
	@mkdir -p bin

# The Unit Tests
.PHONY: tests
$(TESTS): %.out:%.c
	$(CC) $(CFLAGS)  $< -o $@
tests: CFLAGS += $(TARGET) -L$(LIB_PATHS) $(LIBS)
tests: $(TESTS)
	sh ./tests/runtests.sh

valgrind:
	VALGRIND="valgrind --log-file=/tmp/valgrind-%p.log" $(MAKE)

# The Cleaner
clean:
	rm -rf build $(OBJECTS) $(TESTS)
	rm -f tests/tests.log
	find . -name "*.gc" -exec rm {} \;
	rm -rf `find . -name "*.dSYM" -print`

# The Install
install: all
	install -d $(DESTDIR)/$(PREFIX)/lib/
	install $(TARGET) $(DESTDIR)/$(PREFIX)/lib/

# The Checker
BADFUNCS='[^_.>a-zA-Z0-9](str(n?cpy|n?cat|xfrm|n?dup|str|pbrk|tok|_)|stpn?cpy|a?sn?printf|byte_)'
check:
	@echo Files with potentially dangerous functions.
	@egrep $(BADFUNCS) $(SOURCES) || true

