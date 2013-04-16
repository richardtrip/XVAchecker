CC:=gcc
CFLAGS:=-O3 -std=c99 -Wall
LDFLAGS:=-lcrypto -static
OBJ:= main.o 
EXEC:=chkxva_$(shell uname -m)

%.o: %.c 
	$(CC) -c -o $@ $< $(CFLAGS)

$(EXEC): $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f *.o $(EXEC)
