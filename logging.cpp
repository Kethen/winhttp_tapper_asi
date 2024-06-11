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

// windows
#include <windows.h>

// it does not like writing some items and would add random bytes..?
// oh, mingw-w64 write is converting \n to \r\n without O_BINARY on open
//static int log_fd = -1;
static HANDLE log_handle = INVALID_HANDLE_VALUE;
static pthread_mutex_t logging_mutex;

bool can_log(){
	//return log_fd >= 0;
	return log_handle != INVALID_HANDLE_VALUE;
}

int init_logging(){
	int ret = pthread_mutex_init(&logging_mutex, NULL);
	struct timespec time_now;
	clock_gettime(CLOCK_REALTIME, &time_now);
	char path_buf[128];
	sprintf(path_buf, "./winhttp_tapper_log_%u.bin", time_now.tv_sec + time_now.tv_nsec / 1000000000);
	//log_fd = open(path_buf, O_CREAT | O_WRONLY | O_TRUNC);
	log_handle = CreateFileA(path_buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	return ret;
}

struct __attribute__((__packed__)) dump_header{
	uint32_t size;
	uint32_t timestamp;
	uint32_t dump_type;
};

//int total_data_written = 0;

void dump_data(char *data_buf, uint32_t len, uint32_t type){
	//printf("dump_data data_buf 0x%p, len %u, type %u\n", data_buf, len, type);
	//if(log_fd >= 0){
	if(log_handle != INVALID_HANDLE_VALUE){
		struct timespec time_now;
		clock_gettime(CLOCK_REALTIME, &time_now);
		struct dump_header dh = {
			.size = len,
			.timestamp = (uint32_t)(time_now.tv_sec + time_now.tv_nsec / 1000000000),
			.dump_type = type
		};
		pthread_mutex_lock(&logging_mutex);

		int written = 0;
		//int i = 0;
		while(written < sizeof(dump_header)){
			char *write_head = (char *)&dh;
			//int loop_written = write(log_fd, &write_head[written], sizeof(dump_header) - written);
			DWORD loop_written;
			BOOL ret = WriteFile(log_handle, &write_head[written], sizeof(dump_header) - written, &loop_written, NULL);
			//if(loop_written < 0){
			if(!ret){
				// for now, end the application
				exit(1);
			}
			written += loop_written;
			//i++;
		}
		//printf("dump_data wrote %d bytes of header in %d iterations\n", written, i);
		//total_data_written += written;
		written = 0;
		//printf("total data written %d\n", total_data_written);
		//i = 0;
		while(written < len){
			//int loop_written = write(log_fd, &data_buf[written], len - written);
			DWORD loop_written;
			BOOL ret = WriteFile(log_handle, &data_buf[written], len - written, &loop_written, NULL);
			//if(loop_written < 0){
			if(!ret){
				// for now, end the application
				exit(1);
			}
			written += loop_written;
			//i++;
		}
		//printf("dump_data wrote %d bytes of data in %d iterations\n", written, i);
		//total_data_written += written;
		//printf("total data written %d\n", total_data_written);
		pthread_mutex_unlock(&logging_mutex);
	}
}
