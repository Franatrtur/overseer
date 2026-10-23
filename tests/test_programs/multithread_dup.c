#include <pthread.h>
#include <unistd.h>

void* worker(void* arg) {
    (void)arg;
    getpid();
    getpid();
    return NULL;
}

int main(void) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, worker, NULL);
    pthread_create(&t2, NULL, worker, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}
