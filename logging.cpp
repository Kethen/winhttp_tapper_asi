// unix-ish
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

// std
#include <stdio.h>
#include <stdint.h>

// pthread
#include <pthread.h>

// _commit
#include <io.h>

static int log_fd = -1;
static pthread_mutex_t logging_mutex;

bool can_log(){
	return log_fd >= 0;
}

int init_logging(){
	int ret = pthread_mutex_init(&logging_mutex, NULL);
	struct timespec time_now;
	clock_gettime(CLOCK_REALTIME, &time_now);
	char path_buf[64];
	sprintf(path_buf, "./winhttp_tapper_log_%u.bin", time_now.tv_sec + time_now.tv_nsec / 1000000000);
	log_fd = open(path_buf, O_CREAT | O_APPEND | O_WRONLY);
	return ret;
}

struct __attribute__((__packed__)) dump_header{
	uint32_t size;
	uint32_t timestamp;
	uint32_t dump_type;
};

void dump_data(char *data_buf, uint32_t len, uint32_t type){
	if(log_fd >= 0){
		struct timespec time_now;
		clock_gettime(CLOCK_REALTIME, &time_now);
		struct dump_header dh = {
			.size = len,
			.timestamp = (uint32_t)(time_now.tv_sec + time_now.tv_nsec / 1000000000),
			.dump_type = type
		};
		pthread_mutex_lock(&logging_mutex);
		int written = 0;
		while(written < sizeof(dump_header)){
			char *write_head = (char *)&dh;
			int loop_written = write(log_fd, &write_head[written], sizeof(dump_header) - written);
			if(loop_written < 0){
				// from this point on, writes will be misaligned
				// for now, end the application
				exit(1);
			}
			written += loop_written;
		}
		written = 0;
		while(written < len){
			int loop_written = write(log_fd, &data_buf[written], len - written);
			if(loop_written < 0){
				// from this point on, writes will be misaligned
				// for now, end the application
				exit(1);
			}
			written += loop_written;
		}
		pthread_mutex_unlock(&logging_mutex);
	}
}
