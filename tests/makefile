i_paths = ../

varint_test: varint_test.out
	./varint_test.out

varint_test.out: varint_test.o varint.o test.h
	cc -o varint_test.out varint_test.o varint.o

varint_test.o: varint_test.c ../varint.h
	cc -c varint_test.c -I$(i_paths)

varint.o: ../varint.c ../varint.h
	cc -c ../varint.c

clean:
	-rm *.o *.out