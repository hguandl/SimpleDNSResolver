import time
import gzip
import pickle
import logging
import asyncio
from aioudp import open_local_endpoint, open_remote_endpoint

SERVER_ADDR = '0.0.0.0'
SERVER_PORT = 5300

# Upsteam Address, use DNSPod
UPSTREAM_ADDR = '119.29.29.29'
UPSTREAM_PORT = 53

# Duration to cleanup caches
CACHE_TTL = 1800

caches = []

# Query without EDNS
class SimplifiedQuery(object):
    def __init__(self, data):
        self.raw_data = list(data)
        self.id = data[0:2]
        self._parse_question()

    def _parse_question(self):
        # Bypass Header Section
        data = self.raw_data[12:]
        # QNAME ends with 0o0
        end_of_qname = data.index(0o0)
        # QTYPE, QCLASS are the next 4 octet
        self.question = data[:end_of_qname + 5]
        # Query without EDNS
        self.simple_data = self.raw_data[:12 + end_of_qname + 5]
        # Set ARCOUNT to 0
        self.simple_data[11] = 0x0
        self.simple_data = bytes(self.simple_data)


# DNS Answer Cache
class DNSRecord(SimplifiedQuery):
    def __init__(self, _query, _response):
        super().__init__(_response)
        self.query = _query
        self.time = time.time()
        self.ttl = []
        # Record Answer RR Counts
        self.count = int.from_bytes(bytes(self.raw_data[6:8]), byteorder='big')
        # Add Authority RR Counts
        self.count += int.from_bytes(bytes(self.raw_data[8:10]), byteorder='big')
        self._parse_record()

    # Rewrite compare method to use list.index() for searching
    def __eq__(self, _query: SimplifiedQuery) -> bool:
        return self.query.question == _query.question

    def _parse_record(self):
        # Bypass Header & Question Section
        pt = len(self.simple_data)
        rr_cnt = 0
        while rr_cnt < self.count:
            # Bypass NAME
            if self.raw_data[pt] & 0xc0 == 0xc0:
                # Pointer, 2 bytes
                pt += 2
            else:
                # Plain name, ends with 0x0
                while self.raw_data[pt] != 0x0:
                    pt += 1
                pt += 1
            # Bypass TYPE & CLASS
            pt += 4
            # Record the position and value of TTL
            self.ttl.append([pt, int.from_bytes(bytes(self.raw_data[pt:(pt + 4)]), byteorder='big')])
            pt += 4
            # Bypass RLENGTH and RDATA
            rlength = int.from_bytes(bytes(self.raw_data[pt:(pt + 2)]), byteorder='big')
            pt += 2 + rlength
            rr_cnt += 1

    def get_response(self, new_query) -> bytes:
        rr = self.raw_data
        # Use ID from new_query
        rr[0:2] = new_query.id

        # Check the TTL
        t_elapse = int(time.time() - self.time)
        for r_ttl in self.ttl:
            pt = r_ttl[0]
            new_ttl = r_ttl[1] - t_elapse
            if new_ttl <= 0:
                # Update the record from upstream
                self.__init__(self.query, query_upstream(self.query))
                return self.get_response(new_query)
            rr[pt:(pt + 4)] = int.to_bytes(new_ttl, length=4, byteorder='big')

        return bytes(rr)

    def revoked(self) -> bool:
        t_elapse = int(time.time() - self.time)
        for r_ttl in self.ttl:
            new_ttl = r_ttl[1] - t_elapse
            if new_ttl <= 0:
                return True

        return False


async def query_upstream(_query) -> bytes:
    remote = await open_remote_endpoint(UPSTREAM_ADDR, UPSTREAM_PORT)
    remote.send(_query.simple_data)
    _response = await remote.receive()
    return _response

def loadCache() -> list:
    try:
        fp =  gzip.open('cache.gz', 'rb')
        caches = pickle.load(fp)
        fp.close()
        print('Cache file restored')
    except:
        logging.warning('No caches')
        caches = []
    return caches

def saveCache(caches: list):
    try:
        fp = gzip.open('cache.gz', 'wb')
        caches = pickle.dump(caches, fp)
        fp.close()
        print('Dump current cache into file')
    except:
        logging.warning('Dumpping cache failed')

async def main():
    t_start = time.time()

    caches = loadCache()

    local = await open_local_endpoint(SERVER_ADDR, SERVER_PORT)

    print('The server is ready at {}:{}'.format(SERVER_ADDR, SERVER_PORT))

    while True:
        # Cleanup outdated, unpopular cache
        # Dump current cache to file
        if time.time() - t_start >= CACHE_TTL:
            for c in caches:
                if c.revoked():
                    caches.remove(c)
            saveCache(caches)

        message, client_address = await local.receive()
        query = SimplifiedQuery(message)
        try:
            cache = caches[caches.index(query)]
            # The query has already been cached
            response = cache.get_response(query)
        except ValueError:
            # No cached record matched, send query to the upstream server
            response = await query_upstream(query)
            # Add the response to caches
            caches.append(DNSRecord(query, response))
        # server_socket.sendto(response, client_address)
        local.send(response, client_address)

if __name__ == '__main__':
    asyncio.run(main())
