OPTLIBS = -lcrypto -lgmp
LIB_PATHS = /usr/local/opt/openssl/lib
INC_PATHS = /usr/local/opt/openssl/include
CFLAGS = -g -O2 -Wall -Wextra -Isrc -I$(INC_PATHS) -DNDEBUG $(OPTFLAGS)
CXXFLAGS = -g -O2 -Wall -Wextra -Isrc -I$(INC_PATHS) -DNDEBUG $(OPTFLAGS)
LIBS = -ldl $(OPTLIBS)
PREFIX ?= /usr/local

SOURCES = $(wildcard src/**/*.c src/*.c)
OBJECTS = $(patsubst %.c, %.o, $(SOURCES))

TEST_SRC = $(wildcard tests/*_tests.c)
TESTS = $(patsubst %.c, %.out, $(TEST_SRC))

DEBUGS_SRC = $(wildcard debug/*_debug.c)
DEBUGS = $(patsubst %.c,%.out,$(DEBUGS_SRC))

CXX_DEBUGS_SRC = $(wildcard debug/*_debug.cc)
CXX_DEBUGS = $(patsubst %.cc,%.out,$(CXX_DEBUGS_SRC))

TARGET = build/libMY_LIBARAY.a
SO_TARGET = $(patsubst %.a, %.so, $(TARGET))

# The Target Build
all: $(TARGET) $(SO_TARGET) tests

dev: CFLAGS = -g -Wall -Isrc -Wextra -Wextra $(OPTFLAGS)
dev: all

$(TARGET): CFLAGS += -fPIC

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
	$(CC) $(CFLAGS) $< -o $@
tests: CFLAGS += $(TARGET) -L$(LIB_PATHS) $(LIBS)
tests: $(TESTS)
	sh ./tests/runtests.sh

$(DEBUGS):%.out:%.c
	$(CC) $(CFLAGS) $< -o $@

dbg: CFLAGS += $(TARGET) -L$(LIB_PATHS) $(LIBS) -lpthread -lleveldb
dbg: $(DEBUGS)


$(CXX_DEBUGS):%.out:%.cc
	$(CXX) $(CXXFLAGS) $< -o $@

cxx_dbg: CXXFLAGS += $(TARGET) -L$(LIB_PATHS) $(LIBS) -lpthread -lleveldb
cxx_dbg: $(CXX_DEBUGS)


valgrind:
	VALGRIND="valgrind --log-file=/tmp/valgrind-%p.log" $(MAKE)

# The Cleaner
clean:
	rm -rf build $(OBJECTS) $(TESTS) $(CXX_DEBUGS) $(DEBUGS)
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

