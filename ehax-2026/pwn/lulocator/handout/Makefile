PROJECT_ROOT := $(abspath ..)
ADMIN_ROOT   := $(PROJECT_ROOT)/admin
TARGET       := lulocator

.PHONY: all sync verify

all: sync

sync:
	$(MAKE) -C $(ADMIN_ROOT) build verify-sync verify-libc

verify:
	@test -f $(TARGET)
	@test -f libc.so.6
	@echo "[OK] handout contains $(TARGET) and libc.so.6"
