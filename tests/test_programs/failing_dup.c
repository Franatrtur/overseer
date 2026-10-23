#include <unistd.h>
#include <fcntl.h>

int main(void) {
    for (int i = 0; i < 4; i++) {
        open("/nonexistent_path_overseer_test", O_RDONLY);
    }
    return 0;
}
