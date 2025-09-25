#include <stdio.h>
#include <stdlib.h>

void win() {
	system("/bin/sh");
}

void func0() {
	char inp[100];
	printf("Enter the launch command: ");
	gets(inp);
}

void main() {
	fflush(stdout);
	fflush(stdin);
	func0();
}