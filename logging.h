#ifndef _H_LOGGING_
#define _H_LOGGING_

#include <stdio.h>

bool can_log();
int init_logging();
void dump_data(char *data_buf, uint32_t len, uint32_t type);

enum LOG_TYPE {
	LOG_TYPE_LOG = 0,
	LOG_TYPE_REQUEST_HEADER = 1,
	LOG_TYPE_REQUEST_OPTIONAL_DUMP = 2,
	LOG_TYPE_READ_DATA_DUMP = 3,
	LOG_TYPE_WRITE_DATA_DUMP = 4,
	LOG_TYPE_CLOSE_HANDLE = 5,
	LOG_TYPE_CONNECT = 6,
	LOG_TYPE_REQUEST = 7,
};

#define LOG(...){ \
	if(can_log()){ \
		char _logging_buffer[1024]; \
		int _log_len = sprintf(_logging_buffer, __VA_ARGS__); \
		dump_data(_logging_buffer, _log_len, LOG_TYPE_LOG); \
	} \
}

#endif // _H_LOGGING_
