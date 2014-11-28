
import struct
import socket

geoIP = []
f = open('geoipdb.txt', 'r')
for line in f:
    if len(line) > 0 and line[0] != '%':
        geoIP.append(line.split(' '))

def get_cc(query_ip):
    '''
    Because the ip addresses are sorted,
    we will perform binary search to retrieve
    the correct 2-byte country code
    '''
    lo, hi = 0, len(geoIP)-1
    while lo < hi:
        mid = (hi+lo)/2
        if hi-lo == 1:
            if compare_range(query_ip, geoIP[hi][0:2]) == 0:
                return geoIP[hi][2]
            elif compare_range(query_ip, geoIP[lo][0:2]) == 0:
                return geoIP[lo][2]

        if compare_range(query_ip, geoIP[mid][0:2]) < 0:
            hi = mid-1
        elif compare_range(query_ip, geoIP[mid][0:2]) > 0:
            lo = mid+1
        else:
            return geoIP[mid][2].lower().strip()
    return None


def compare_range(ip, rng):

    low = int(struct.unpack('!L', socket.inet_aton(rng[0]))[0])
    high = int(struct.unpack('!L', socket.inet_aton(rng[1]))[0])
    target = int(struct.unpack('!L', socket.inet_aton(ip))[0])
    if target < low:
        return -1
    elif low <= target and target <= high:
        return 0
    elif target > high:
        return 1

def main():
    correct = ['EU', 'EU', 'EU', 'EU', 'AU', 'TW']
    test = ['2.16.8.13', '2.16.8.0', '5.23.31.255', '5.23.31.231', '223.255.255.0', '223.138.0.0']
    result = []
    for t in test:
        result.append(get_cc(t))

    correct = [c.lower() for c in correct]
    compare = zip(result, correct)
    print compare
    print [a == b for a,b in compare]

if __name__ == '__main__':
    main()
    