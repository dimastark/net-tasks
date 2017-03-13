import time
import struct


def parse_records(name, data, counts):
    """ Parse 'count' records in data """
    records = []
    pointer = 0
    packets = data[2:].split(b'\xc0\x0c')
    for count in counts:
        rrs = []
        for i in range(count):
            try:
                rrs.append(RR(name, b'\xc0\x0c' + packets[pointer + i], time.time()))
            except IndexError:
                break
        records.append(rrs)
        pointer += count
    return records


class DNSPacket:
    """DNSPacket class"""
    def __init__(self, data):
        self.len_name = 0
        self._bytes = data
        self.header = list(struct.unpack('!HHHHHH', self._bytes[0:12]))
        self._query_name = None
        self._query_name = self.query_name
        oth = data[12 + len(self.query_name) + 5:]
        self.records = parse_records(self.query_name, oth, self.header[3:])

    @property
    def id(self):
        return self.header[0]

    @id.setter
    def id(self, packet_id):
        self.header[0] = packet_id

    @property
    def query_name(self):
        if not self._query_name:
            ln = self._bytes[12:].find(b'\x00')
            self.len_name = ln
            name = self._bytes[12:12 + ln]
            return struct.unpack(str(ln) + 's', name)[0]
        return self._query_name

    def __bytes__(self):
        ln = len(self.query_name)
        b_header = struct.pack('!HHHHHH', *self.header)
        off = 13 + ln
        b_name = struct.pack(str(ln) + 's', self.query_name) + b'\x00'
        b_rrs = b''.join([bytes(r) for rrs in self.records for r in rrs])
        return b_header + b_name + self._bytes[off:off + 4] + b_rrs


class RR:
    """ DNS resource record """
    def __init__(self, record_name, record_data, record_time):
        self._bytes = record_data
        self._ttl = int.from_bytes(self._bytes[6:10] or '\x00', byteorder='big')
        self.name = record_name
        self.time = record_time

    def __bytes__(self):
        return self._bytes

    @property
    def ttl(self):
        self._ttl = int(self._ttl - time.time() + self.time)
        return self._ttl
