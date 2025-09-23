import socket
import struct
import datetime

# Field IDs must match the Go program
EVENT_TYPE_FIELD_ID = 34001
PROCESS_NAME_FIELD_ID = 34000

def ip_from_int(ip_int):
    return socket.inet_ntoa(struct.pack('!I', ip_int))

def time_from_epoch(epoch):
    return datetime.datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')

def parse_variable_string(data, offset):
    str_len = data[offset]
    offset += 1
    value = data[offset:offset+int(str_len)].decode('utf-8', errors='ignore')
    offset += int(str_len)
    return value, offset

def parse_ipfix(data):
    try:
        version, length, export_time, seq_num, domain_id = struct.unpack('!HHIII', data[:16])
        print(f"--- IPFIX Message Header ---")
        print(f"Version: {version}, Length: {length}, Sequence: {seq_num}, Export Time: {time_from_epoch(export_time)}")
    except struct.error:
        print("Error: Could not unpack IPFIX message header.")
        return

    offset = 16
    templates = {}

    while offset < len(data):
        try:
            flowset_id, flowset_length = struct.unpack('!HH', data[offset:offset+4])
            if flowset_length == 0:
                break
        except struct.error:
            print(f"Error: Could not unpack FlowSet header at offset {offset}.")
            break

        if flowset_id == 2: # Template Set
            template_offset = offset + 4
            while template_offset < offset + flowset_length:
                try:
                    template_id, field_count = struct.unpack('!HH', data[template_offset:template_offset+4])
                    fields = []
                    template_offset += 4
                    for _ in range(field_count):
                        field_type, field_len = struct.unpack('!HH', data[template_offset:template_offset+4])
                        fields.append((field_type, field_len))
                        template_offset += 4
                    templates[template_id] = fields
                except struct.error:
                    break
            offset += flowset_length
            continue

        if flowset_id in templates: # Data Set
            print(f"\n--- Data FlowSet (ID={flowset_id}, Length={flowset_length}) ---")
            record_offset = offset + 4
            record_end = offset + flowset_length

            while record_offset < record_end:
                try:
                    current_pos = record_offset
                    flow_values = {}
                    
                    # Dynamically parse record based on template
                    for field_type, field_len in templates[flowset_id]:
                        if current_pos >= record_end: raise IndexError("Not enough data for template fields")
                        
                        if field_len == 0xFFFF: # Variable length
                            str_len = data[current_pos]
                            current_pos += 1
                            value = data[current_pos:current_pos+int(str_len)].decode('utf-8', errors='ignore')
                            current_pos += int(str_len)
                        else:
                            # Ensure we don't read past the end of the flowset for fixed fields either
                            if current_pos + int(field_len) > record_end:
                                raise IndexError("Not enough data for fixed-size field")
                            value = data[current_pos:current_pos+int(field_len)]
                            current_pos += int(field_len)
                        flow_values[field_type] = value

                    # Assign and Print
                    src_ip, = struct.unpack('!I', flow_values[8])
                    dst_ip, = struct.unpack('!I', flow_values[12])
                    src_port, = struct.unpack('!H', flow_values[7])
                    dst_port, = struct.unpack('!H', flow_values[11])
                    proto, = struct.unpack('!B', flow_values[4])
                    timestamp, = struct.unpack('!I', flow_values[150])
                    event_type = flow_values.get(EVENT_TYPE_FIELD_ID, '?')
                    process_name = flow_values.get(PROCESS_NAME_FIELD_ID, 'unknown')

                    print(f"  - Session Event:")
                    print(f"    Time    : {time_from_epoch(timestamp)}")
                    print(f"    Event   : {event_type.upper()}")
                    print(f"    Process : {process_name}")
                    print(f"    5-Tuple : {ip_from_int(src_ip)}:{src_port} -> {ip_from_int(dst_ip)}:{dst_port} (Proto: {proto})")

                    # The next record starts immediately after this one ends.
                    record_offset = current_pos

                except (struct.error, IndexError, KeyError) as e:
                    print(f"Error processing record, skipping to next flowset: {e}")
                    break # On error, break out of the record loop for this flowset
            
            offset += flowset_length
        else:
            print(f"Encountered data for unknown Template ID: {flowset_id}. Stopping parse.")
            break

UDP_IP = "0.0.0.0"
UDP_PORT = 4739

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"IPFIX decoder listening on UDP port {UDP_PORT}")

while True:
    data, addr = sock.recvfrom(65535)
    print(f"\n{'='*50}")
    print(f"Received {len(data)} bytes from {addr}")
    parse_ipfix(data)
    print(f"{ '='*50}\n")