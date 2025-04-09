// go:build ignore

#include <stdio.h>
#include <unistd.h>

void call_number(int n) {
	printf("Call number %d\n", n);
}

int main() {
	for(int i = 0; i < 10000; i++) {
		call_number(i);
		sleep(1);
	}
	printf("Done\n");
	return 0;
}
