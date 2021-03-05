import struct

# PACKETS


def get_min_packets(connections):
    min_packets = len(connections[0]["packets"])
    for connection in connections:
        if len(connection["packets"]) < min_packets:
            min_packets = len(connection["packets"])
    return min_packets


def get_mean_packets(connections):
    num_packets = 0
    for connection in connections:
        num_packets += len(connection["packets"])
    return num_packets / len(connections)


def get_max_packets(connections):
    max_packets = len(connections[0]["packets"])
    for connection in connections:
        if len(connection["packets"]) > max_packets:
            max_packets = len(connection["packets"])
    return max_packets


# WINDOW SIZE


def get_min_window_size(connections):
    min_window_size = connections[0]["packets"][0].TCP_header.window_size
    for connection in connections:
        for packet in connection["packets"]:
            if packet.TCP_header.window_size < min_window_size:
                min_window_size = packet.TCP_header.window_size
    return min_window_size


def get_mean_window_size(connections):
    mean_window_size = 0
    num_packets = 0
    for connection in connections:
        for packet in connection["packets"]:
            mean_window_size += packet.TCP_header.window_size
            num_packets += 1
    return mean_window_size / num_packets


def get_max_window_size(connections):
    max_window_size = connections[0]["packets"][0].TCP_header.window_size
    for connection in connections:
        for packet in connection["packets"]:
            if packet.TCP_header.window_size > max_window_size:
                max_window_size = packet.TCP_header.window_size
    return max_window_size


# CONNECTION DETAILS


def get_src_to_dst(connection):
    src_to_dst_packets = []
    for p in connection["packets"]:
        packet_connection_id = (
            str(p.TCP_header.src_port)
            + str(p.IP_header.src_ip)
            + str(p.TCP_header.dst_port)
            + str(p.IP_header.dst_ip)
        )
        # print("Packet ID: ", packet_connection_id)
        # print("Connection ID: ", connection["id"])
        if packet_connection_id == connection["id"]:
            src_to_dst_packets.append(p)
    return src_to_dst_packets


def get_dst_to_src(connection):
    dst_to_src_packets = []
    for p in connection["packets"]:
        packet_connection_reverse_id = (
            str(p.TCP_header.dst_port)
            + str(p.IP_header.dst_ip)
            + str(p.TCP_header.src_port)
            + str(p.IP_header.src_ip)
        )
        # print("Packet Reverse ID: ", packet_connection_reverse_id)
        # print("Connection ID: ", connection["id"])
        if packet_connection_reverse_id == connection["id"]:
            dst_to_src_packets.append(p)
    return dst_to_src_packets


def get_status(connection):
    status = "S" + str(connection["SYN"]) + "F" + str(connection["FIN"])
    if connection["RST"] >= 1:
        status += "\R"
    return status


def get_start_time(connection):
    for p in connection["packets"]:
        if p.TCP_header.flags["SYN"] == 1:
            return p.timestamp


def get_end_time(connection):
    last_fin = None
    for p in connection["packets"]:
        if p.TCP_header.flags["FIN"] == 1:
            last_fin = p
    return last_fin.timestamp


def get_num_bytes_src_to_dst(connection):
    num_bytes = 0
    packets = get_src_to_dst(connection)
    for p in packets:
        payload = (
            p.packet_length - 14 - p.IP_header.ip_header_len - p.TCP_header.data_offset
        )
        num_bytes += payload
    return num_bytes


def get_duration(connection):
    return get_end_time(connection) - get_start_time(connection)


def get_num_bytes_dst_to_src(connection):
    num_bytes = 0
    packets = get_dst_to_src(connection)
    for p in packets:
        payload = (
            p.packet_length - 14 - p.IP_header.ip_header_len - p.TCP_header.data_offset
        )
        num_bytes += payload
    return num_bytes


def format_timestamp(time):
    m = int(time % 3600 // 60)
    s = time % 3600 % 60
    if m == 0:
        return "{:02f}s".format(s)
    return "{:2d}m {:02f}s".format(m, s)


def get_min_time(connections):
    min_time = get_duration(connections[0])
    for connection in connections:
        if get_duration(connection) < min_time:
            min_time = get_duration(connection)
    return min_time


def get_mean_time(connections):
    total = 0
    for connection in connections:
        total += get_duration(connection)
    return total / len(connections)


def get_max_time(connections):
    max_time = get_duration(connections[0])
    for connection in connections:
        if get_duration(connection) > max_time:
            max_time = get_duration(connection)
    return max_time


def get_min_rtt(connections):
    min_rtt = connections[0]["packets"][0].RTT_value
    for connection in connections:
        for packet in connection["packets"]:
            if packet.RTT_value < min_rtt:
                min_rtt = packet.RTT_value
    return min_rtt


def get_mean_rtt(connections):
    total = 0
    num_packets = 0
    for connection in connections:
        for packet in connection["packets"]:
            total += packet.RTT_value
            num_packets += 1
    return total / num_packets


def get_max_rtt(connections):
    max_rtt = connections[0]["packets"][0].RTT_value
    for connection in connections:
        for packet in connection["packets"]:
            if packet.RTT_value > max_rtt:
                max_rtt = packet.RTT_value
    return max_rtt


class IP_Header:
    src_ip = None  # <type 'str'>
    dst_ip = None  # <type 'str'>
    ip_header_len = None  # <type 'int'>
    total_len = None  # <type 'int'>

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0

    def ip_set(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def header_len_set(self, length):
        self.ip_header_len = length

    def total_len_set(self, length):
        self.total_len = length

    def get_IP(self, buffer1, buffer2):
        src_addr = struct.unpack("BBBB", buffer1)
        dst_addr = struct.unpack("BBBB", buffer2)
        s_ip = (
            str(src_addr[0])
            + "."
            + str(src_addr[1])
            + "."
            + str(src_addr[2])
            + "."
            + str(src_addr[3])
        )
        d_ip = (
            str(dst_addr[0])
            + "."
            + str(dst_addr[1])
            + "."
            + str(dst_addr[2])
            + "."
            + str(dst_addr[3])
        )
        self.ip_set(s_ip, d_ip)

    def get_header_len(self, value):
        result = struct.unpack("B", value)[0]
        length = (result & 15) * 4
        self.header_len_set(length)

    def get_total_len(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        length = num1 + num2 + num3 + num4
        self.total_len_set(length)


class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size = 0
    checksum = 0
    ugp = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size = 0
        self.checksum = 0
        self.ugp = 0

    def src_port_set(self, src):
        self.src_port = src

    def dst_port_set(self, dst):
        self.dst_port = dst

    def seq_num_set(self, seq):
        self.seq_num = seq

    def ack_num_set(self, ack):
        self.ack_num = ack

    def data_offset_set(self, data_offset):
        self.data_offset = data_offset

    def flags_set(self, ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin

    def win_size_set(self, size):
        self.window_size = size

    def get_src_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        port = num1 + num2 + num3 + num4
        self.src_port_set(port)
        # print(self.src_port)
        return None

    def get_dst_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        port = num1 + num2 + num3 + num4
        self.dst_port_set(port)
        # print(self.dst_port)
        return None

    def get_seq_num(self, buffer):
        seq = struct.unpack(">I", buffer)[0]
        self.seq_num_set(seq)
        # print(seq)
        return None

    def get_ack_num(self, buffer):
        ack = struct.unpack(">I", buffer)[0]
        self.ack_num_set(ack)
        return None

    def get_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        fin = value & 1
        syn = (value & 2) >> 1
        rst = (value & 4) >> 2
        ack = (value & 16) >> 4
        self.flags_set(ack, rst, syn, fin)
        return None

    def get_window_size(self, buffer1, buffer2):
        buffer = buffer2 + buffer1
        size = struct.unpack("H", buffer)[0]
        self.win_size_set(size)
        return None

    def get_data_offset(self, buffer):
        value = struct.unpack("B", buffer)[0]
        length = ((value & 240) >> 4) * 4
        self.data_offset_set(length)
        # print(self.data_offset)
        return None

    def relative_seq_num(self, orig_num):
        if self.seq_num >= orig_num:
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        # print(self.seq_num)

    def relative_ack_num(self, orig_num):
        if self.ack_num >= orig_num:
            relative_ack = self.ack_num - orig_num + 1
            self.ack_num_set(relative_ack)


class packet:
    # pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    packet_length = 0
    packet_orig_length = 0
    packet_data = None
    buffer = None

    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        # self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No = 0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.packet_length = 0
        self.packet_orig_length = 0

    def timestamp_set(self, buffer1, buffer2, orig_sec, orig_usec):
        secs = struct.unpack("I", buffer1)[0]
        usecs = struct.unpack("<I", buffer2)[0]
        orig_time = orig_sec + orig_usec * 0.000001
        self.timestamp = round(secs + usecs * 0.000001 - orig_time, 6)

    def packet_No_set(self, number):
        self.packet_No = number
        # print(self.packet_No)

    def set_packet_length(self, incl_len, orig_len):
        self.packet_length = incl_len
        self.packet_orig_length = orig_len

    def get_RTT_value(self, p):
        rtt = p.timestamp - self.timestamp
        self.RTT_value = round(rtt, 8)


packets = []
packet_number = 0
orig_sec = None
orig_usec = None
firstPacket = True

connections = []

with open("./sample-capture-file.cap", "rb") as f:
    global_header = f.read(24)  # We don't do anything with this
    while True:
        # For each packet
        data = f.read(16)
        if not data:
            break
        else:
            # PACKET CONFIG
            p = packet()
            ts_sec = data[0:4]
            ts_usec = data[4:8]
            incl_len = data[8:12]
            orig_len = data[12:16]
            SYN = 0
            FIN = 0
            RST = 0
            if firstPacket:
                orig_sec = struct.unpack("I", ts_sec)[0]
                orig_usec = struct.unpack("I", ts_usec)[0]
            p.timestamp_set(ts_sec, ts_usec, orig_sec, orig_usec)

            firstPacket = False
            packet_length = struct.unpack("I", incl_len)[0]
            packet_orig_len = struct.unpack("I", orig_len)[0]
            p.set_packet_length(packet_length, packet_orig_len)

            p.packet_No_set(packet_number)
            packet_number = packet_number + 1

            packet_data = f.read(packet_length)

            # IP HEADER
            p.IP_header.get_header_len(packet_data[14:15])
            p.IP_header.get_total_len(packet_data[16:18])
            p.IP_header.get_IP(packet_data[26:30], packet_data[30:34])

            tcp_start_index = 14 + p.IP_header.ip_header_len

            # TCP HEADER
            p.TCP_header.get_src_port(
                packet_data[tcp_start_index : tcp_start_index + 2]
            )
            p.TCP_header.get_dst_port(
                packet_data[tcp_start_index + 2 : tcp_start_index + 4]
            )
            p.TCP_header.get_seq_num(
                packet_data[tcp_start_index + 4 : tcp_start_index + 8]
            )
            p.TCP_header.get_ack_num(
                packet_data[tcp_start_index + 8 : tcp_start_index + 12]
            )
            p.TCP_header.get_data_offset(
                packet_data[tcp_start_index + 12 : tcp_start_index + 13]
            )
            p.TCP_header.get_flags(
                packet_data[tcp_start_index + 13 : tcp_start_index + 14]
            )
            p.TCP_header.get_window_size(
                packet_data[tcp_start_index + 14 : tcp_start_index + 15],
                packet_data[tcp_start_index + 15 : tcp_start_index + 16],
            )

            if p.TCP_header.flags["SYN"] == 1:
                SYN = 1
            if p.TCP_header.flags["FIN"] == 1:
                FIN = 1
            if p.TCP_header.flags["RST"] == 1:
                RST = 1

            # Fetch details for 4-tuple
            packet_connection_id = (
                str(p.TCP_header.src_port)
                + str(p.IP_header.src_ip)
                + str(p.TCP_header.dst_port)
                + str(p.IP_header.dst_ip)
            )

            packet_connection_reverse_id = (
                str(p.TCP_header.dst_port)
                + str(p.IP_header.dst_ip)
                + str(p.TCP_header.src_port)
                + str(p.IP_header.src_ip)
            )

            connectionExists = False
            for connection in connections:
                if (
                    connection["id"] == packet_connection_id
                    or connection["id"] == packet_connection_reverse_id
                ):  # Connection already exists, add it to the list
                    connectionExists = True
                    connection["packets"].append(p)
                    connection["SYN"] = SYN + connection["SYN"]
                    connection["FIN"] = FIN + connection["FIN"]
                    connection["RST"] = RST + connection["RST"]

            if not connectionExists:
                connections.append(
                    {
                        "id": packet_connection_id,
                        "src_port": p.TCP_header.src_port,
                        "src_ip": p.IP_header.src_ip,
                        "dst_port": p.TCP_header.dst_port,
                        "dst_ip": p.IP_header.dst_ip,
                        "packets": [p],
                        "SYN": SYN,
                        "FIN": FIN,
                        "RST": RST,
                    }
                )
            packets.append(packet)
            print()

    # Set up counts
    connection_num = 1
    num_reset_connections = 0
    num_complete_connections = 0

    complete_connections = []

    # TOTAL NUMBER OF CONNECTIONS
    print("A) Total number of connections: ", len(connections))
    print()

    # CONNECTIONS' DETAILS
    print("B) Connections' Details: ")
    print()
    for connection in connections:
        print("Connection " + str(connection_num) + ":")
        print("Source Address: ", connection["src_ip"])
        print("Destination Address: ", connection["dst_ip"])
        print("Source Port: ", connection["src_port"])
        print("Destination Port: ", connection["dst_port"])
        print("Status: ", get_status(connection))
        if connection["SYN"] > 0 and connection["FIN"] > 0:  # Connection is complete
            complete_connections.append(connection)
            print("Start Time: ", format_timestamp(get_start_time(connection)))
            print("End Time: ", format_timestamp(get_end_time(connection)))
            print(
                "Duration: ",
                format_timestamp(get_end_time(connection) - get_start_time(connection)),
            )
            print(
                "Number of packets sent from Source to Destination: ",
                len(get_src_to_dst(connection)),
            )
            print(
                "Number of packets sent from Destination to Source: ",
                len(get_dst_to_src(connection)),
            )
            print(
                "Total number of packets: ",
                str(len(get_dst_to_src(connection)) + len(get_src_to_dst(connection))),
            )
            print(
                "Number of data bytes sent from Source to Destination: ",
                str(get_num_bytes_src_to_dst(connection)),
            )
            print(
                "Number of data bytes sent from Destination to Source: ",
                str(get_num_bytes_dst_to_src(connection)),
            )
            print(
                "Total number of data bytes: ",
                get_num_bytes_src_to_dst(connection)
                + int(get_num_bytes_dst_to_src(connection)),
            )
            print("END")
            if connection_num != len(connections):
                print("+++++++++++++++++++++++++++++++++")
        if connection["RST"] > 0:
            num_reset_connections += 1
        connection_num += 1
    num_open_connections = len(connections) - len(complete_connections)
    print()

    # GENERAL
    print("C) General")
    print()
    print("Total number of complete TCP connections: ", len(complete_connections))
    print("Number of reset TCP connections: ", num_reset_connections)
    print(
        "Number of TCP connections that were still open when trace capture ended: ",
        num_open_connections,
    )
    print()

    # COMPLETE TCP CONNECTIONS

    print("D) Complete TCP connections: ")
    print()
    print(
        "Minimum time duration: ", format_timestamp(get_min_time(complete_connections))
    )
    print("Mean time duration: ", format_timestamp(get_mean_time(complete_connections)))
    print(
        "Maximum time duration: ", format_timestamp(get_max_time(complete_connections))
    )
    print()
    print("Minimum RTT value: ", get_min_rtt(complete_connections)) # TODO: FIX THIS
    print("Mean RTT value: ", get_mean_rtt(complete_connections)) # TODO: FIX THIS
    print("Maximum RTT value: ", get_max_rtt(complete_connections)) # TODO: FIX THIS
    print()
    print(
        "Minimum number of packets including both send/received: ",
        get_min_packets(complete_connections),
    )
    print(
        "Mean number of packets including both send/received: ",
        get_mean_packets(complete_connections),
    )
    print(
        "Maximum number of packets including both send/received: ",
        get_max_packets(complete_connections),
    )
    print()
    print(
        "Minimum receive window size including both send/received: "
        + str(get_min_window_size(complete_connections))
        + " bytes"
    )
    print(
        "Mean receive window size including both send/received: "
        + str(get_mean_window_size(complete_connections))
        + " bytes"
    )
    print(
        "Maximum receive window size including both send/received: "
        + str(get_max_window_size(complete_connections))
        + " bytes"
    )
