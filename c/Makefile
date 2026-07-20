LIB_NAME = Rijndael
LIB_FNAME = lib$(LIB_NAME).a

CC = gcc
CFLAGS = -Wall -Wextra -std=c23
ifdef DEBUG
	CFLAGS += -g
else
	CFLAGS += -DNDEBUG -O3
endif

SRC_DIR = source
INC_DIR = include
OBJ_DIR = obj
LIB_DIR = lib
TEST_DIR = test

SRCS = $(wildcard $(SRC_DIR)/*.c)
HDRS = $(wildcard $(INC_DIR)/*.h)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

TARGET = $(LIB_DIR)/$(LIB_FNAME)
TEST_SRC = $(TEST_DIR)/test.c
TEST_OBJ = $(TEST_DIR)/test.o
TEST_EXEC = $(TEST_DIR)/test

# Rule to compile object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HDRS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to build library
$(TARGET): $(OBJS)
	@mkdir -p $(@D)
	ar rcs $@ $^

# Rule to build test object file
$(TEST_OBJ): $(TEST_SRC) $(HDRS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to build test executable
$(TEST_EXEC): $(TEST_OBJ) $(TARGET)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJ) $(TARGET)

.DEFAULT_GOAL = build

.PHONY: all build test install clean uninstall

all: build test

build: $(TARGET)

test: $(TEST_EXEC)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/lib
	for header in $(HDRS); do \
		sudo cp $$header /usr/local/include/; \
	done

clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR) $(TEST_OBJ) $(TEST_EXEC)

uninstall:
	if [ -f /usr/local/lib/$(LIB_FNAME) ]; then \
		sudo rm /usr/local/lib/$(LIB_FNAME); \
	fi

	for header in $(HDRS); do \
		header_name=$$(basename $$header); \
		if [ -f /usr/local/include/$$header_name ]; then \
			sudo rm /usr/local/include/$$header_name; \
		fi \
	done

