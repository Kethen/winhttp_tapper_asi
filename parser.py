import sys
import json

path = sys.argv[1]
file = open(path, "rb")

LOG_TYPE_LOG = 0
LOG_TYPE_REQUEST_HEADER = 1
LOG_TYPE_REQUEST_OPTIONAL_DUMP = 2
LOG_TYPE_READ_DATA_DUMP = 3
LOG_TYPE_WRITE_DATA_DUMP = 4
LOG_TYPE_CLOSE_HANDLE = 5
LOG_TYPE_CONNECTION = 6
LOG_TYPE_REQUEST = 7

endian = "little"

'''
uint32_t size
uint32_t timestamp
uint32_t type
'''
header_size = 4 * 3
def read_header(f):
	header_bytes = f.read(header_size)
	if len(header_bytes) != header_size:
		return False

	size = int.from_bytes(header_bytes[0:4], endian)
	timestamp = int.from_bytes(header_bytes[4:8], endian)
	type = int.from_bytes(header_bytes[8:12], endian)
	return {
		"size":size,
		"timestamp":timestamp,
		"type":type,
		"raw":header_bytes
	}

def try_decode(b):
	try:
		s = b.decode("utf-8")
		try:
			j = json.loads(s)
			return json.dumps(j, indent=2)
		except:
			return s
	except:
		return "cannot decode, hex string: " + b.hex()

def parse_file(f):
	requests = {}
	connections = {}

	data_only = open(f"{path}.data_only.txt", "w")
	data_and_log = open(f"{path}.data_and_log.txt", "w")

	def wrapup_request(requests, handle, data_only, data_and_log):
		if handle not in requests:
			return
		request = requests[handle]
		to_write = f"--- request {handle:016x} begin ---\n"

		if "resource" in request:
			resource = request["resource"]
			to_write = to_write + f"resource: {resource}\n"

		if "header" in request:
			header = request["header"]
			to_write = to_write + f"header: {header}\n"

		if "optional" in request:
			optional = request["optional"]
			to_write = to_write + "optional:\n"
			to_write = to_write + f"{optional}\n"

		if "write" in request:
			write = request["write"]
			bytes_written = try_decode(write)
			to_write = to_write + "bytes written:\n"
			to_write = to_write + f"{bytes_written}\n"

		if "read" in request:
			read = request["read"]
			bytes_read = try_decode(read)
			to_write = to_write + "bytes read:\n"
			to_write = to_write + f"{bytes_read}\n"

		to_write = to_write + f"--- request {handle:016x} end ---\n"

		data_only.write(to_write)
		data_and_log.write(to_write)

		del requests[handle]

	last_header = None
	while True:
		header = read_header(f)
		if header == False:
			print("end of file reached during header read")
			break

		payload_size = header["size"]
		payload = f.read(payload_size)
		payload_len = len(payload)
		if payload_len != payload_size:
			print(f"end of file reached during payload read, header size {payload_size}, read size {payload_len}")
			print(f"header {header}")
			if last_header is not None:
				print(f"last header {last_header}")
			break

		type = header["type"]
		if type == LOG_TYPE_CONNECTION:
			handle = int.from_bytes(payload[0:8], endian)
			server = payload[8:].decode("utf-8")
			connections[handle] = server

		elif type == LOG_TYPE_REQUEST:
			connection_handle = int.from_bytes(payload[0:8], endian)
			handle = int.from_bytes(payload[8:16], endian)
			method_resource = payload[16:].decode("utf-8").split("|")
			method = method_resource[0]
			resource = method_resource[1]
			if handle not in requests:
				requests[handle] = {}
			request = requests[handle]
			if connection_handle in connections:
				request["resource"] = f"{method}:{connections[connection_handle]}/{resource}"
			else:
				request["resource"] = f"{method}:<capture failed>/{resource}"

		elif type == LOG_TYPE_REQUEST_HEADER:
			handle = int.from_bytes(payload[0:8], endian)
			if handle not in requests:
				requests[handle] = {}
			request = requests[handle]
			request["header"] = try_decode(payload[8:])

		elif type == LOG_TYPE_REQUEST_OPTIONAL_DUMP:
			handle = int.from_bytes(payload[0:8], endian)
			if handle not in requests:
				requests[handle] = {}
			request = requests[handle]
			request["optional"] = try_decode(payload[8:])

		elif type == LOG_TYPE_WRITE_DATA_DUMP:
			handle = int.from_bytes(payload[0:8], endian)
			if handle not in requests:
				requests[handle] = {}
			request = requests[handle]
			if "write" not in request:
				request["write"] = b''
			request["write"] = request["write"] + payload[8:]

		elif type == LOG_TYPE_READ_DATA_DUMP:
			handle = int.from_bytes(payload[0:8], endian)
			if handle not in requests:
				requests[handle] = {}
			request = requests[handle]
			if "read" not in request:
				request["read"] = b''
			request["read"] = request["read"] + payload[8:]

		elif type == LOG_TYPE_CLOSE_HANDLE:
			handle = int.from_bytes(payload[0:8], endian)
			wrapup_request(requests, handle, data_only, data_and_log)

		elif type == LOG_TYPE_LOG:
			timestamp = header["timestamp"]
			to_write = f"--- log begin {timestamp} ---\n"
			to_write = to_write + try_decode(payload) + "\n"
			to_write = to_write + f"--- log end {timestamp} ---\n"
			data_and_log.write(to_write)

		else:
			print(f"bad type {type}")
			print(f"header {header}")
			if last_header is not None:
				print(f"last_header {last_header}")
			break

		last_header = header

	for handle in list(requests.keys()):
		wrapup_request(requests, handle, data_only, data_and_log)

	data_only.close()
	data_and_log.close()
parse_file(file)
