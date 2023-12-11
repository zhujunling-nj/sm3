''' SM3 Hash '''
from struct import pack, unpack, unpack_from
try:
    from _sm3 import sm3_hash, sm3_hmac
    FAST = True
except ImportError:
    FAST = False

IV = (
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
)

T_J =  (0x79cc4519, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a)


def rotl(value, cnt):
    ''' 32bits left shift'''
    return value << cnt & 0xFFFFFFFF | value >> (32 - cnt)

def xor256(data1, data2):
    ''' 256 bits xor '''
    idata1 = unpack('4Q', data1)
    idata2 = unpack('4Q', data2)
    return pack('4Q',
        idata1[0] ^ idata2[0],
        idata1[1] ^ idata2[1],
        idata1[2] ^ idata2[2],
        idata1[3] ^ idata2[3]
    )

def _xorpad(data, pad):
    ''' Xor bytes of data and pad '''
    idata = unpack('8Q', data)
    return pack('8Q',
        idata[0] ^ pad, idata[1] ^ pad,
        idata[2] ^ pad, idata[3] ^ pad,
        idata[4] ^ pad, idata[5] ^ pad,
        idata[6] ^ pad, idata[7] ^ pad
    )

def _get_w(data, offset):
    w_array = list(unpack_from('>16I', data, offset))
    for j in range(16, 68):
        xxx = w_array[j-16] ^ w_array[j-9] ^ rotl(w_array[j-3], 15)
        w_array.append(xxx ^ rotl(xxx, 15) ^ rotl(xxx, 23)  # p1(xxx)
                       ^ rotl(w_array[j-13], 7) ^ w_array[j-6])
    w1_array = [w_array[j] ^ w_array[j+4] for j in range(64)]
    return w_array, w1_array


def _cf(vector, data, offset=0):
    # pylint: disable=too-many-locals
    w_array, w1_array = _get_w(data, offset)
    aaa, bbb, ccc, ddd, eee, fff, ggg, hhh = vector

    for j in range(0, 16):
        ss1 = rotl(((rotl(aaa, 12)) + eee + (rotl(T_J[j>>4], j & 31))) & 0xFFFFFFFF, 7)
        ss2 = ss1 ^ rotl(aaa, 12)
        tt1 = ((aaa ^ bbb ^ ccc) + ddd + ss2 + w1_array[j]) & 0xFFFFFFFF
        tt2 = ((eee ^ fff ^ ggg) + hhh + ss1 + w_array[j]) & 0xFFFFFFFF
        ddd = ccc
        ccc = rotl(bbb, 9)
        bbb = aaa
        aaa = tt1
        hhh = ggg
        ggg = rotl(fff, 19)
        fff = eee
        eee = tt2 ^ rotl(tt2, 9) ^ rotl(tt2, 17)  # p0(t2)

    for j in range(16, 64):
        ss1 = rotl(((rotl(aaa, 12)) + eee + (rotl(T_J[j>>4], j & 31))) & 0xFFFFFFFF, 7)
        ss2 = ss1 ^ rotl(aaa, 12)
        tt1 = ((aaa & bbb | aaa & ccc | bbb & ccc) + ddd + ss2 + w1_array[j]) & 0xFFFFFFFF
        tt2 = ((eee & fff | ~eee & ggg) + hhh + ss1 + w_array[j]) & 0xFFFFFFFF
        ddd = ccc
        ccc = rotl(bbb, 9)
        bbb = aaa
        aaa = tt1
        hhh = ggg
        ggg = rotl(fff, 19)
        fff = eee
        eee = tt2 ^ rotl(tt2, 9) ^ rotl(tt2, 17)  # p0(t2)

    return (
        aaa ^ vector[0],
        bbb ^ vector[1],
        ccc ^ vector[2],
        ddd ^ vector[3],
        eee ^ vector[4],
        fff ^ vector[5],
        ggg ^ vector[6],
        hhh ^ vector[7]
    )


def _padding(data, total):
    padlen = 56 - ((total + 1) & 63)
    if padlen < 0:
        padlen += 64
    data += pack(f'>B{padlen}xQ', 128, total<<3)
    return data


def _sm3_hash(data):
    ''' SM3 Hash '''
    vector = IV
    datalen = len(data)
    len64 = datalen - (datalen & 63)
    for pos in range(0, len64, 64):
        vector = _cf(vector, data, pos)
    data = _padding(data[len64:], datalen)
    for pos in range(0, len(data), 64):
        vector = _cf(vector, data, pos)
    return pack('>8I', *vector)


_BLOCK_SIZE = 64
_IPAD = 0x3636363636363636
_OPAD = 0x5C5C5C5C5C5C5C5C
def _sm3_hmac(key, data):
    ''' SM3 HMac Hash '''
    if len(key) > _BLOCK_SIZE:
        key = sm3_hash(key)
    key = key.ljust(_BLOCK_SIZE, b'\0')
    hashv = sm3_hash(_xorpad(key, _IPAD) + data)
    return sm3_hash(_xorpad(key, _OPAD) + hashv)


def pbkdf2(password, salt, iterations, dklen=32):
    ''' Password-based key derivation function 2. '''
    result = bytearray()
    blk_cnt = (dklen + 31) >> 5
    for idx in range(1, blk_cnt + 1):
        salt_i4 = salt + pack('>I', idx)
        hmac_result = sm3_hmac(password, salt_i4)
        xor_result = hmac_result
        for _ in range(1, iterations):
            hmac_result = sm3_hmac(password, hmac_result)
            xor_result = xor256(xor_result, hmac_result)
        # Concatenate the blocks
        result.extend(xor_result)
    return result[:dklen]


class SM3:
    ''' SM3 Hash Class '''
    __slots__ = ['buffer', 'length', 'outbuf']

    def __init__(self, data=b''):
        self.buffer = bytearray(data)
        self.length = len(data)
        self.outbuf = IV
        len64 = len(self.buffer)
        len64 = len64 - (len64 & 63)
        for pos in range(0, len64, 64):
            self.outbuf = _cf(self.outbuf, self.buffer, pos)
        self.buffer = self.buffer[len64:]

    @classmethod
    def new(cls, data=b''):
        ''' Create a new hashing object. '''
        return cls(data)

    @property
    def name(self):
        ''' The hash algorithm being used by this object. '''
        return 'sm3'

    @property
    def digest_size(self):
        ''' The size of the resulting hash in bytes.. '''
        return 32

    @property
    def block_size(self):
        ''' The block size of the hash algorithm in bytes. '''
        return 64

    def copy(self):
        ''' Return a copy of the current hash object. '''
        obj = self.__class__()
        obj.buffer = self.buffer.copy()
        obj.length = self.length
        obj.outbuf = self.outbuf
        return obj

    def update(self, data):
        ''' Updat the current digest with an additional string. '''
        self.buffer.extend(data)
        self.length += len(data)
        len64 = len(self.buffer)
        len64 = len64 - (len64 & 63)
        for pos in range(0, len64, 64):
            self.outbuf = _cf(self.outbuf, self.buffer, pos)
        self.buffer = self.buffer[len64:]

    def digest(self):
        ''' Return the current digest value as bytes. '''
        self.buffer = _padding(self.buffer, self.length)
        for pos in range(0, len(self.buffer), 64):
            self.outbuf = _cf(self.outbuf, self.buffer, pos)
        self.outbuf = bytearray()
        return pack('>8I', *self.outbuf)

    def hexdigest(self):
        ''' Return the current digest as hexadecimal string. '''
        return self.digest().hex()


if not FAST:
    sm3_hash = _sm3_hash
    sm3_hmac = _sm3_hmac
