
__author__      = "Bhavin Shah"

import socket
import struct
import random
import time
import select
import six
import sys
import getopt

t_echo_req = 8
t_echo_reply = 0
t_ttl_exceeded = 11

icmp_echo_code = 0
icmp = socket.getprotobyname('icmp')


def checksum(str):
    """
    This function finds checksum of a given input string
    :param str: input string
    :return: checksum
    """
    csum = 0
    i = 0

    while (i + 1) < len(str):
        if six.PY3:
            csum += str[i + 1] * 256 + str[i]
        else:
            csum += ord(str[i + 1]) * 256 + ord(str[i])
        csum &= 0xffffffff
        i += 2

    if i < len(str):
        if six.PY3:
            csum += ord(str[i])
        else:
            csum += str[i]
        csum &= 0xffffffff

    # add high 16 bits to low 16 bits
    csum = (csum >> 16) + (csum & 0xffff)
    # add carry
    csum += (csum >> 16)
    csum = ~csum
    csum &= 0xffff

    if sys.byteorder == 'little':
        return csum
    else:
        return socket.htons(csum)


def is_valid(addr):
    """
    This function return true if the given address is valid ip address, false otherwise
    :param addr: address
    :return: boolean
    """
    parts = addr.split(".")
    if not len(parts) == 4:
        return False
    for i in parts:
        try:
            part = int(i)
        except ValueError:
            return False
        else:
            if part > 255 or part < 0:
                return False
    return True


def to_ip(addr):
    """
    This function converts a given address to ip address
    :param addr: address
    :return: ip address
    """
    if is_valid(addr):
        return addr
    return socket.gethostbyname(addr)


def get_packet(pkt_id, sequence):
    """
    This function creates a icmp packet with given packet id, sequence number
    :param pkt_id:
    :param sequence:
    :return:
    """
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # ctype: signed char, signed char, unsigned short, unsigned short, short
    my_checksum= 0
    header = struct.pack("bbHHh", t_echo_req, icmp_echo_code, my_checksum, pkt_id, sequence)
    data = struct.pack("d", time.time())

    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', t_echo_req, icmp_echo_code, my_checksum, pkt_id, sequence)

    packet = header + data
    return packet


def print_unknown_host(e):
    print("Unable to resolve target system name " + str(e))


def get_host(to_host, cur_ip):
    """
    This function returns a tuple containing domain name and ip address if possible and to_host=true, else ip address
    :param to_host:
    :param cur_ip:
    :return:
    """
    try:
        if to_host:
            cur_name = socket.gethostbyaddr(cur_ip)[0]
            return "%s [%s]" % (cur_name, cur_ip)
        else:
            return "%s" % cur_ip
    except socket.error:
        return cur_ip
    else:
        return None


def tracert(dest, no_of_probes = 3, to_host = True, print_summary = False, max_ttl= 30):
    """
    This function tracerotes a given target location
    :param dest:
    :param no_of_probes:
    :param to_host: if true ip addresses are converted to domain names
    :param print_summary:
    :param max_ttl:
    :return:
    """

    try:
        dest_ip = to_ip(dest)
    except socket.gaierror:
        print_unknown_host(dest)
        return
    else:
        print("")
        if is_valid(dest_ip):
            print("Tracing route to %s [%s]" % (dest, dest_ip))
        else:
            print("Tracing route to %s" % (dest_ip))
        print("over a maximum of %d hops:\n" % max_ttl)

    ttl = 1
    port = 1337
    sequence = 0
    timeout = 1
    f_probes = {}


    while ttl <= max_ttl:

        cur_ip = None
        cur_host = None

        print(ttl, end='\t')
        for i in range(0, no_of_probes):
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            soc.bind(("", port))
            soc.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            pkt_id = int(timeout * 1000 * random.random()) % 65535

            delay = 0
            fails = 0
            t_sent = time.time()
            soc.sendto(get_packet(pkt_id, sequence), (dest_ip, port))

            while delay < timeout:

                ready = select.select([soc], [], [], timeout-delay)

                if not ready[0]:  # Timeout
                    fails += 1
                    print("*", end='\t')
                    break
                else:
                    delay = (time.time() - t_sent)
                    rec_packet, (cur_ip, _) = soc.recvfrom(1024)
                    r_type, r_code, r_csum, r_p_id, r_seq = struct.unpack('bbHHh', rec_packet[20:28])
                    if r_type == t_ttl_exceeded:
                        print(str(int(delay * 1000)) + " ms", end='\t')
                        cur_host = get_host(to_host, cur_ip)
                        break
                    elif r_type == t_echo_reply and r_p_id == pkt_id:
                        cur_host = get_host(to_host, cur_ip)
                        print(str(int(delay * 1000)) + " ms", end='\t')
                        break
            soc.close()
            sequence += 1

        if cur_host is None:
            print("Request timed out.")
        else:
            print(cur_host)

        f_probes[ttl] = fails

        if (cur_ip is not None) and (cur_ip == dest_ip):
            print("Trace complete.")
            if print_summary:
                summary(f_probes)
            break

        ttl += 1


def summary(dict):
    """
    This function prints summary of # of probes that were not answered for each hop
    :param dict: ttl vs probes not answered
    :return:
    """
    print("\nSummary:")
    for key, value in dict.items():
        print("%d : %d probes failed" % (key, value))

def usage():
    print("")
    print("Usage: ping [-n] [-q nqueries] [-S] target_name")
    print("Options:")
    print("    -n             Print hop addresses numerically rather than symbolically and numerically.")
    print("    -q nqueries    Number of probes per ttl to send.")
    print("    -S             Prints a summary of how many probes were not answered for each hop.")

if __name__ == "__main__":

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hnq:S', '--help')

    except getopt.GetoptError:
        print("Not a valid command option.")
        usage()
        sys.exit(0)

    to_host = True
    no_of_probes = 3
    print_summary = False

    try:
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                usage()
                sys.exit(0)
            elif opt == '-n':
                to_host = False
            elif opt == '-q':
                no_of_probes = int(arg)
            elif opt == '-S':
                print_summary = True

    except ValueError:
        print("Error parsing options.")
        usage()

    else:
        if len(args) <= 0:
            print("A target name or address must be specified.")
            usage()
        else:
            tracert(args[0], no_of_probes, to_host, print_summary)

