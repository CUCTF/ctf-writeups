.PHONY: all clean

all: linux-skel-6.13.4

# Build linux-skel-6.13.4 using Docker if it doesn't exist
linux-skel-6.13.4:
	docker build -o linux-skel-6.13.4 -t linux-skel -f Dockerfile.build .

# Clean target to remove generated directory
clean:
	rm -rf linux-skel-6.13.4