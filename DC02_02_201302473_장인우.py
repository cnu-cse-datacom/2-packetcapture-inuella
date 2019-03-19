import socket
import struct

start_num = 0
select_tcp_udp = 0
'''ip헤더의 길이값을 이용해 tcp/udp헤더의 시작점을 알 수 있고 protocol을 이용해 tcp인지 udp인지 알 수있다
   parsing_ip_header함수에서 값을 기록해 다른 함수에서 쓰기위해 전역변수로 선언 '''


def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)  # !는 빅엔디안, c는 문자, s는 문자열
    ether_src = convert_ethernet_address(
        ethernet_header[0:6])  # source address(6byte) : 출발지 주소
    # destination address(6byte) : 목적지 주소
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    # - Ethernet type(2byte) : 상위계층 프로토콜 종류를 표시(IP 일 경우 0x0800)
    ether_ip_header = "0x"+ethernet_header[12].hex()
    print("======ethernet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ether_ip_header)


# 언팩된 이더넷헤더는 (b'\x0c', b'\x8b', b'\xfd', b'\x85', b'\x87', b' ')이런식의 바이트 행렬이다
def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())  # 바이트형의 값들을 16진수 문자형으로 변환하면서 리스트에 추가
    ethernet_addr = ":".join(ethernet_addr)  # "구분기호".join // 리스트 원소 사이에 구분자 추가
    return ethernet_addr


def parsing_ip_header(data):
    ip_header = struct.unpack('!1s1s2s2s2s1s1s2s4s4s', data)
    ip_version = (int(ip_header[0].hex(), 16)) >> 4
    # ip헤더길이는 워드단위므로 4를 곱한다 예를들어 ip_header_length가 5면 사실 20바이트이다
    ip_header_length = ((int(ip_header[0].hex(), 16)) & 15) * 4
    # dscp는 ip_header[1] 의 왼쪽부터 6비트만큼이 나타내므로
    dscp = int(ip_header[1].hex(), 16) >> 2
    # ecn은 ip_header[1]의 맨 오른쪽 두비트가 나타내므로
    ecn = int(ip_header[1].hex(), 16) & 3
    ip_total_length = ip_header[2].hex()
    ip_identification = ip_header[3].hex()
    ip_flags = ip_header[4].hex()
    #flag_dont_fragment 비트는 2바이트크기 ip_header[4]의 2번째 비트가 나타낸다 비트연산을 위해 int()로 변환후 연산한다
    flag_dont_fragment = (int(ip_header[4].hex(), 16) >> 14) & 1
    #flag_fragment 비트는 3번째 비트이다 위와 같은 방법으로 추출한다
    flag_fragment = (int(ip_header[4].hex(), 16) >> 13) & 1
    # ip_fragment 값은  ip_header[4] 에서 ip_flags가 나타내는 맨 왼쪽 3개의 비트값을 제거하면 구할 수있다
    ip_fragment = (int(ip_header[4].hex(), 16)) << 3 >> 3
    ip_ttl = ip_header[5].hex()
    ip_protocol = ip_header[6].hex()
    ip_checksum = ip_header[7].hex()
    ip_src_addr = ip_header[8].hex()
    ip_dst_addr = ip_header[9].hex()
    print("=================================================")
    print("\tIPv4")
    print("=================================================")
    print("ip_version : ", ip_version)
    print("ip_Length : ", ip_header_length)
    print("dscp : ", dscp)
    print("ecn : ", ecn)
    print("Total length : ", int(ip_total_length, 16))
    print("Identification : ", int(ip_identification, 16))
    print("flags : 0x"+ip_flags)
    print(">>>reserved_bit: 0")  # 이 비트는 항상 0이므로
    print(">>>not_fragments: ", flag_dont_fragment)
    print(">>>fragments: ", flag_fragment) D D 
    print(">>>fragment_offset: ", ip_fragment)
    print("Time To Live: ", int(ip_ttl, 16))
    print("Protocol: ", int(ip_protocol, 16))
    print("Header Checksum: ", int(ip_checksum, 16))
    print("src_IP address: "+make_ip_address(ip_src_addr))
    print("dst_IP address: "+make_ip_address(ip_dst_addr))
    global start_num, select_tcp_udp # start_num, select_tcp_udp가 전역변수임을 알려줌
    start_num = 14+ip_header_length # 이더넷헤더의 길이 14와 ip헤더의 길이를 더해주면 tcp/udp헤더의 시작점을 알 수 있다
    select_tcp_udp = int(ip_protocol, 16) # ip헤더의 protocol값이 6이면 tcp헤더를 사용한다


def make_ip_address(addr_integer):
    addr = ""
    for i in range(0, 7, 2):
        temp_addr = int(addr_integer[i:i+2], 16)
        if i != 6:  # i는 0,2,4,6 으로 변한다 이때 6이면 ip주소의 맨마지막이므로 점을 찍으면 안된다
            # 문자형태의 숫자를 더하면 123 + 456 = 123456 이 됨을 이용하여 점을 추가하기위해 숫자를 문자형으로 바꿔준다
            addr += str(temp_addr)+"."
        else:
            addr += str(temp_addr)
    return addr


def parsing_tcp_header(data):

    TCP_header = struct.unpack(
        '!2s2s4s4s2s2s2s2s', data)

    print("=================================================")
    print("\tTCP Header")
    print("=================================================\n")
    print("src_Port :", int(TCP_header[0].hex(), 16))
    print("dst_Port :", int(TCP_header[1].hex(), 16))
    print("Sequence Number :", int(TCP_header[2].hex(), 16))
    print("Ackonwledge Number :", int(TCP_header[3].hex(), 16))
    # data offset은 각 flag들의 합으로 이루어져있다
    print("Data offset :", int(TCP_header[4].hex()[0:1], 16))
    # hex는 문자형이다 int로 변환하면 어떤 플래그가 1인지 알 수 있다
    cal_offset = int(TCP_header[4].hex(), 16)
    # Reserved (3 비트) 미래에 사용하기 위해 남겨둔 예비 필드이며 0으로 채워져야 한다.
    print(">>>reserved : 0 ")
    print(">>>nonce :", (cal_offset & 256) >> 9)
    # data offset이 0x018 일경우 -> 10진수 int로 변환하면 24이다 -> 24는 000011000 -> 따라서 ACK와 PSH가 1임을 알수있다
    print(">>>cwr :", (cal_offset & 128) >> 7)
    print(">>>ece :", (cal_offset & 64) >> 6)
    print(">>>urgent :", (cal_offset & 32) >> 5)
    print(">>>ack :", (cal_offset & 16) >> 4)
    print(">>>push :", (cal_offset & 8) >> 3)
    print(">>>reset :", (cal_offset & 4) >> 2)
    print(">>>syn :", (cal_offset & 2) >> 1)
    print(">>>fin :", (cal_offset & 1))

    print("Window Size :", int(TCP_header[5].hex(), 16))
    print("TCP checksum :", int(TCP_header[6].hex(), 16))
    print("Urgent Pointer :", int(TCP_header[7].hex(), 16))


def parsing_udp_header(data):
    UDP_header = struct.unpack('!2s2s2s2s', data)
    print("=================================================")
    print("\tUDP Header")
    print("=================================================\n")
    # int( X , 16 ) 이것은 X는 16진수고 문자형태인데 이것을 10진수로 고치고 int형으로 바꾸겠다는 의미
    print("src_Port : ", int(UDP_header[0].hex(), 16))
    print("dst_Port : ", int(UDP_header[1].hex(), 16))
    print("leng : ", int(UDP_header[2].hex(), 16))
    print("header checksum : 0x"+UDP_header[3].hex())



recv_socket = socket.socket(
    socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))


while True:

    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    parsing_ip_header(data[0][14:34])

    if select_tcp_udp == 6:  # ip헤더의 ip protocol을 통해 tcp인지 udp인지 구별한다
        # ip헤더의 길이가 유동적이므로 start_num 변수를 이용해 ip헤더길이에 따라 tcp/udp헤더의 시작점을 설정
        parsing_tcp_header(data[0][start_num:start_num+20])
    elif select_tcp_udp == 17:
        parsing_udp_header(data[0][start_num:start_num+8])
    break
