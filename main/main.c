#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define DEVICE "/dev/net_sniffer"

int main() {
    int fd;
    char buffer[256];
    ssize_t bytes_read;

    fd = open(DEVICE, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open the device...");
        return errno;
    }

    printf("Reading from the device...\n");
    bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read < 0) {
        perror("Failed to read the message from the device.");
        return errno;
    }

    printf("The received message is: [%s]\n", buffer);
    close(fd);

    return 0;
}

