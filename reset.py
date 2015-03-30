import socket, sys, struct
from socket import socket, htons, AF_INET, AF_PACKET, SOCK_DGRAM, SOCK_RAW, IP_HDRINCL, IPPROTO_IP, IPPROTO_RAW, SOL_SOCKET
ETH_P_IP = 8
TCP = 6
SO_BINDTODEVICE = 25
ps = socket(AF_PACKET, SOCK_DGRAM, ETH_P_IP);
ps.bind((sys.argv[1], htons(ETH_P_IP)));
rs = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
rs.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, sys.argv[1])
#rs.setsockopt(IPPROTO_IP, IP_HDRINCL, 1);
port = int(sys.argv[2])

def get_ip_str(ip_num):
    return '.'.join(str(octet) for octet in struct.unpack('!BBBB', struct.pack('!I', ip_num)))

def unpack_ipv4_header(ip_header):
    version_ihl, dscp_ecn, total_len, ident, flags_frag_offset, ttl, protocol, checksum, src_ip, dst_ip = struct.unpack('!BBHHHBBHII', ip_header[:20])
    return {'ihl': version_ihl & 0xF, 'protocol': protocol, 'src_ip': src_ip, 'dst_ip': dst_ip, 'ident': ident, 'ttl': ttl};

def unpack_tcp_header(tcp_header):
    src_port,dst_port,seq_num,ack_num,info_1,info_2,window_size,checksum = struct.unpack('!HHIIBBHH', tcp_header[:18])
    return {'src_port': src_port, 'dst_port': dst_port, 'seq_num': seq_num, 'ack_num': ack_num, 'data_offset': (info_1 & 0xF0) >> 4, 'flags': {'ns': info_1 & 0x1, 'cwr': info_2 & 0x80, 'ece': info_2 & 0x40, 'urg': info_2 & 0x20, 'ack': info_2 & 0x10, 'psh': info_2 & 0x8, 'rst': info_2 & 0x4, 'syn': info_2 & 0x2, 'fin': info_2 & 0x1}, 'window_size': window_size, 'checksum': checksum}

def pack_ipv4_header(version, ihl, dscp, ecn, total_len, ident, flags, frag_offset, ttl, protocol, checksum, src_addr, dst_addr):
    return struct.pack("!BBHHHBBHII", (version << 4) | ihl, ((dscp & 0x3F) << 2) | (ecn & 0x3), total_len, ident, ((flags & 0x7) << 13) | (frag_offset & 0x1FFF), ttl, protocol, checksum, src_addr, dst_addr)

def pack_tcp_header(src_port, dst_port, seq_num, ack_num, data_offset, ns, cwr, ece, urg, ack, psh, rst, syn, fin, window_size, checksum, urg_ptr):
    return struct.pack("!HHIIBBHHH", src_port, dst_port, seq_num, ack_num, ((data_offset & 0xF) << 4) | (ns & 1), ((cwr & 1) << 7) | ((ece & 1) << 6) | ((urg & 1) << 5) | ((ack & 1) << 4) | ((psh & 1) << 3) | ((rst & 1) << 2) | ((syn & 1) << 1) | (fin & 1), window_size, checksum, urg_ptr)

def tcp_checksum(unpacked_ipv4_header, packed_tcp_header, data_len, payload):
    data = struct.pack('!IIBBH', unpacked_ipv4_header['src_ip'], unpacked_ipv4_header['dst_ip'], 0, TCP, data_len + 20) + packed_tcp_header + payload
    s = 0
    for i in range(0, len(data), 2):
        w = struct.unpack('!H', data[i:i+2])[0]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def forge_response(ivp4_header, tcp_header, data):
            data_len = 0
            if data != None:
                data_len = len(data)
    
            def forge_tcp_header(cur_checksum):
                    return pack_tcp_header(
                    src_port=tcp_header['src_port'],
                    dst_port=tcp_header['dst_port'],
                    seq_num=tcp_header['seq_num']+len(tcp_data),
                    ack_num=tcp_header['ack_num'],
                    data_offset=5,
                    ns=0,
                    cwr=0,
                    ece=0,
                    urg=0,
                    ack=1,
                    psh=1 if data_len != 0 else 0,
                    rst=0,
                    syn=0,
                    fin=0,
                    window_size=tcp_header['window_size'],
                    checksum=cur_checksum,
                    urg_ptr=0)
            response_ipv4_header = pack_ipv4_header(version=4,
                    ihl=ipv4_header['ihl'],
                    dscp=0,
                    ecn=0,
                    total_len=40 + data_len,
                    ident=ipv4_header['ident']+1,
                    flags=0x02,
                    frag_offset=0,
                    ttl=ipv4_header['ttl'],
                    protocol=TCP,
                    checksum=0,
                    src_addr=ipv4_header['src_ip'],
                    dst_addr=ipv4_header['dst_ip'])
            response_tcp_without_checksum = forge_tcp_header(0)
            my_tcp_checksum=tcp_checksum(ipv4_header,
                    response_tcp_without_checksum, data_len, data)
            response_tcp_header = forge_tcp_header(my_tcp_checksum)
            header = response_ipv4_header + response_tcp_header
            if data != None:
                return header + data
            else:
                return header

while True:
    data, addr = ps.recvfrom(4096)
    ipv4_header = unpack_ipv4_header(data)
    if ipv4_header['protocol'] == TCP:
        tcp_header = unpack_tcp_header(data[ipv4_header['ihl'] * 4:])
        tcp_data = data[(ipv4_header['ihl'] * 4) + (tcp_header['data_offset'] * 4):]
        if len(tcp_data) > 0 and (tcp_header['src_port'] == port or tcp_header['dst_port'] == port) and tcp_data != 'TEST\n\n':
            print "saw message on port"
            rs.sendto(forge_response(ipv4_header, tcp_header, 'TEST\n\n'), ('127.0.0.1', 0))

