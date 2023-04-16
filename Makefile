CC := g++
CFLAGS := -Wall -Wextra -pedantic -std=c++20
BUILD_DIR := ./build-objects/
TARGET := ./ipk-l4-scan

# Adds optimizations or debug info
ifeq ($(release),1)
	CFLAGS += -o3
else
	CFLAGS += -g3
endif

# Makes the compilation crash on warnings
ifeq ($(strict),1)
	CFLAGS += -Werror
endif

$(shell mkdir ${BUILD_DIR} 2>/dev/null)

OBJ = $(patsubst %.cc,$(BUILD_DIR)/%.o,$(wildcard *.cc))

.PHONY: all run test clean pack

all: $(TARGET)

run: all
	./$(TARGET)

clean:
	rm ./$(BUILD_DIR)/*.o 2>/dev/null
	rm ./$(TARGET) 2>/dev/null
	rm xzobal01.zip 2>/dev/null ||true

pack: *.cc *.hh *.md Makefile LICENSE
	zip xzobal01.zip $^

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) && echo "OK" >/dev/stderr

# Building all the object files
$(BUILD_DIR)/%.o: %.cc
	$(CC) $(CFLAGS) -c -o $@ $<
