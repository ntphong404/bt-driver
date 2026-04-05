CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I../driver
TARGET  = file_manager
SRC     = file_manager.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

# Chạy thử nhanh
test: all
	@echo "Hello, CAMELLIA World!" > /tmp/test.txt
	./$(TARGET) encrypt /tmp/test.txt
	./$(TARGET) list /tmp
	./$(TARGET) view /tmp/test.txt.enc
	./$(TARGET) decrypt /tmp/test.txt.enc
	@echo "--- File gốc sau giải mã ---"
	@cat /tmp/test.txt
