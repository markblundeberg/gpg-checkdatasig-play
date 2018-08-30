""" Mini parser for gpg packets """

import hashlib
import attr
import ecdsa
from collections import namedtuple

__all__ = ['ParseError', 'SubPacket', 'PubKeyPacketV4', 'SigPacketV4', 'read_packet', 'read_packets' ]

class ParseError(Exception):
    pass

def parse_length(view):
    """ Read a variable length. Return its size and value.
    https://tools.ietf.org/html/rfc4880#section-5.2.3.1

    One-byte for lengths up to 191
    Two-byte for lengths of 191 to 8383
    Five-byte for lengths of up to 4294967295 (2**32-1)
    """
    try:
        b0 = view[0]
        if b0 < 192: # up to 191
            return 1, b0
        if b0 < 224:
            b1 = view[1]
            return 2, ((b0-192)<<8) + (b1) + 192
        if b0 == 255: # up to 2**32-1
            b1,b2,b3,b4 = view[1:5]
            return 5, (b1 << 24) + (b2 << 16) + (b3 << 8) + (b4)
        raise ParseError("cannot handle partial body length headers")
        # 192 to 254
    except (IndexError, ValueError):
        raise ParseError("truncated mid-length")

def serialize_length(l):
    """ Returns minimal length prefix (note length prefix is not unique),
    in new style."""
    l = int(l)
    if l < 0:
        raise ValueError(l)
    elif l < 192:
        return bytes((l,))
    elif l < 8384:
        x = l - 192
        b0 = (x >> 8) + 192
        b1 = x & 0xff
        return bytes((b0, b1))
    elif l <= 4294967295:
        return b'\xff' + l.to_bytes(4,'big')
    else:
        raise OverflowError(l)

SPT = namedtuple('SPType', 'name parsefunc')
SPtime = lambda x: int.from_bytes(x, 'big')
SPhex = 'hex'
SPbool = lambda x: x != b'\0'
SPstr = lambda x: x
SPTres = SPT("Reserved", None)
SPTunk = SPT("Unknown", None)

subpacket_types = {
    0:  SPTres,
    1:  SPTres,
    2:  SPT("Signature Creation Time", SPtime),
    3:  SPT("Signature Expiration Time", SPtime),
    4:  SPT("Exportable Certification", SPbool),
    5:  SPT("Trust Signature", lambda x:(x[0], x[1])),
    6:  SPT("Regular Expression", SPstr),
    7:  SPT("Revocable", SPbool),
    8:  SPTres,
    9:  SPT("Key Expiration Time", SPtime),
    10: SPT("Placeholder for backward compatibility", None),
    11: SPT("Preferred Symmetric Algorithms", tuple),
    12: SPT("Revocation Key", lambda x:(x[0],x[1],x[2:].hex())),
    13: SPTres,
    14: SPTres,
    15: SPTres,
    16: SPT("Issuer", SPhex),
    17: SPTres,
    18: SPTres,
    19: SPTres,
    20: SPT("Notation Data", None),
    21: SPT("Preferred Hash Algorithms", tuple),
    22: SPT("Preferred Compression Algorithms", tuple),
    23: SPT("Key Server Preferences", SPhex),
    24: SPT("Preferred Key Server", SPstr),
    25: SPT("Primary User ID", SPbool),
    26: SPT("Policy URI", SPstr),
    27: SPT("Key Flags", SPhex),
    28: SPT("Signer's User ID", SPstr),
    29: SPT("Reason for Revocation", lambda x:(x[0], SPstr(x[1:]))),
    30: SPT("Features", SPhex),
    31: SPT("Signature Target", lambda x:(x[0],x[1],x[2:].hex())),
    32: SPT("Embedded Signature", None),
    }

class SubPacket:
    def __init__(self, sptype, spdata):
        self.sptype = int(sptype)
        self.spdata = bytes(spdata)
        self._spprefix_content = None
        self._spprefix = None

    def __repr__(self,):
        info = subpacket_types.get(self.sptype, SPTunk)
        if info.parsefunc is None:
            prepr = "%d bytes"%(len(self.spdata))
        elif info.parsefunc == "hex":
            prepr = self.spdata.hex().upper()
        else:
            try:
                prepr = repr(info.parsefunc(self.spdata))
            except:
                prepr = "parse error"

        return '<SubPacket [%d]%s: %s>'%(self.sptype, info.name, prepr)

    @property
    def spprefix(self,):
        l = 1 + len(self.spdata)
        if self._spprefix is None or self._spprefix_content != l:
            self._spprefix = serialize_length(l)
            self._spprefix_content = l
        return self._spprefix

    def __len__(self,):
        return len(self.spprefix) + 1 + len(self.spdata)

    def to_bytes(self,):
        return self.spprefix + bytes((self.sptype,)) + self.spdata

    @classmethod
    def from_bytes(cls, raw):
        view = memoryview(raw)
        lenlen,splen = parse_length(view)
        sptype = view[lenlen]
        totallen = 1 + lenlen + splen
        spdata = bytes(view[1 + lenlen : lenlen + splen])
        if 1 + len(spdata) != splen:
            raise ParseError("truncated subpacket")
        self = cls(sptype, spdata)
        self._spprefix = bytes(view[:lenlen])
        self._spprefix_content = splen
        return self

def parse_subpackets(view):
    subpackets = []
    while view:
        spkt = SubPacket.from_bytes(view)
        view = view[len(spkt):]
        subpackets.append(spkt)
    return subpackets

def serialize_subpackets(subpackets):
    """Return bytes representation of subpackets list, including
    the 2-byte length prefix."""
    ba = bytearray()
    for spkt in subpackets:
        ba.extend(spkt.to_bytes())
    balen = len(ba).to_bytes(2, 'big')
    return balen + ba

def parse_mpis(view):
    """Parse multiprecision integer list

    https://tools.ietf.org/html/rfc4880#section-3.2
    """
    mpis = []
    while view:
        ilen_bits = (view[0] << 8) + view[1]
        ilen_bytes = (ilen_bits + 7) // 8
        idat = view[2:2+ilen_bytes]
        if len(idat) != ilen_bytes:
            raise ParseError("truncated integer")
        ival = int.from_bytes(idat, 'big', signed=False)
        if ival.bit_length() != ilen_bits:
            raise ParseError("non-minimal MPI encoding")
        mpis.append(ival)
        view = view[2+ilen_bytes:]
    return mpis

def serialize_mpis(mpis):
    ba = bytearray()
    for i in mpis:
        i = int(i)
        assert(i>=0)
        ilen_bits = i.bit_length()
        ilen_bytes = (ilen_bits + 7) // 8
        idat = i.to_bytes(ilen_bytes, 'big')
        ba.extend(ilen_bits.to_bytes(2,'big'))
        ba.extend(i.to_bytes(ilen_bytes,'big'))
    return ba

@attr.s(cmp=False)
class PubKeyPacketV4:
    """ https://tools.ietf.org/html/rfc4880#section-5.5.2
    """
    version = 4

    creation_time = attr.ib(None)
    pubalgo = attr.ib(None)

    oid = attr.ib(None) # oid field for ECC
    mpis = attr.ib(factory=list) # list of "multiprecision integers"
    keydata = attr.ib(None) # for algos we don't know about

    @classmethod
    def from_bytes(cls, raw):
        self = cls()
        self._deserialize(raw)
        return self

    def _deserialize(self,raw):
        raw = bytes(raw)
        assert(raw[0] == self.version)

        view = memoryview(raw)

        self.creation_time = int.from_bytes(view[1:5],'big')
        self.pubalgo = view[5]

        if self.pubalgo <= 17:
            i = 6
        elif self.pubalgo in [19, 22]:
            oidlen = view[6]
            assert(0 < oidlen < 0xff)
            self.oid = bytes(view[7:7+oidlen])
            assert(len(self.oid) == oidlen)
            i = 7 + oidlen
        else:
            self.keydata = bytes(view[6:])
            return

        self.mpis = parse_mpis(view[i:])

    def to_bytes(self):
        serdat = bytearray([self.version])
        serdat.extend(self.creation_time.to_bytes(4,'big'))
        serdat.append(self.pubalgo)
        if self.pubalgo <= 17:
            serdat.extend(serialize_mpis(self.mpis))
        elif self.pubalgo in [19, 22]:
            serdat.append(len(self.oid))
            serdat.extend(self.oid)
            serdat.extend(serialize_mpis(self.mpis))
        else:
            serdat.extend(self.keydata)
        return bytes(serdat)

    def canonical_packet(self):
        """ Return serialized with canonical prexfix [0x99, lmaj, lmin] prefix
        as used in keyID calculation and in certification.

        keyID = sha1(this.canonical_packet())

        cert_digest = hashalgo(this.canonical_packet()
                               + uidpacket.canonical_packet()
                               + sigpacket.trailer())

        - https://tools.ietf.org/html/rfc4880#section-12.2
        - https://tools.ietf.org/html/rfc4880#section-5.2.4
        """
        ser = self.to_bytes()
        lendat = len(ser).to_bytes(2,'big')
        return b'\x99' + lendat + ser

    def key_id(self):
        return hashlib.sha1(self.canonical_packet()).digest()

@attr.s(cmp=False)
class SigPacketV4:
    """ https://tools.ietf.org/html/rfc4880#section-5.2.3
    """
    version = 4

    #  0-binary doc ; 1-text doc ; 16 - generic certification ; ...
    sigtype = attr.ib(None) # https://tools.ietf.org/html/rfc4880#section-5.2.1

    # integers according to https://tools.ietf.org/html/rfc4880#section-9
    pubalgo = attr.ib(None)
    hashalgo = attr.ib(None)

    # lists of subpackets
    subpkts_hashed = attr.ib(factory=list)  # hashed -- stuff that is included in signed data.
    subpkts_unhashed = attr.ib(factory=list) # unhashed -- anyone can add info here.

    hash2 = attr.ib(None) # 2 bytes

    mpis = attr.ib(factory=list) # list of "multiprecision integers"

    @classmethod
    def from_bytes(cls, raw):
        self = cls()
        self._deserialize(raw)
        return self

    def _deserialize(self,raw):
        raw = bytes(raw)
        assert(raw[0] == self.version)

        view = memoryview(raw)

        self.sigtype = view[1]
        self.pubalgo = view[2]
        self.hashalgo = view[3]
        i = 4

        # Hashed subpackets
        given_length = (view[i] << 8) + view[i+1]
        i += 2
        spdat = view[i:i+given_length]
        if len(spdat) != given_length:
            raise ParseError("truncated subpackets")
        self.subpkts_hashed = parse_subpackets(spdat)
        i += given_length

        # Check that everything up to this point can be reproduced.
        if self.trailer(partial=True) != raw[:i]:
            raise RuntimeError('Deserialized signature data cannot be reproduced.')

        # Unhashed subpackets
        given_length = (view[i] << 8) + view[i+1]
        i += 2
        spdat = view[i:i+given_length]
        if len(spdat) != given_length:
            raise ParseError("truncated subpackets")
        self.subpkts_unhashed = parse_subpackets(spdat)
        i += given_length

        self.hash2 = bytes(view[i:i+2])
        if len(self.hash2) != 2:
            raise ParseError("truncated hash2")

        self.mpis = parse_mpis(view[i+2:])

        # We could check here that full serialization yields `raw` but
        # this is not so critical.

    def trailer(self, *, partial=False):
        """ Return the trailer for this kind of signature. The trailer
        gets appended to the signed data just before it is hashed.

        A=<signature data from version byte (4) up to end of hashed subpackets>
        B=<0x04 0xFF>
        C=<len(A) as 4-byte big endian unsigned>

        returns concatenation A+B+C

        (if partial=True, just returns A)
        """
        serdat = bytearray([
                self.version,
                self.sigtype,
                self.pubalgo,
                self.hashalgo])
        serdat.extend(serialize_subpackets(self.subpkts_hashed))
        if partial:
            return serdat
        lbytes = len(serdat).to_bytes(4,'big')
        return b''.join((serdat, b'\x04\xff', lbytes))

    def to_bytes(self,):
        serdat = bytearray([
                self.version,
                self.sigtype,
                self.pubalgo,
                self.hashalgo])
        serdat.extend(serialize_subpackets(self.subpkts_hashed))
        serdat.extend(serialize_subpackets(self.subpkts_unhashed))
        hash2 = bytes(self.hash2)
        assert(len(hash2) == 2)
        serdat.extend(hash2)
        serdat.extend(serialize_mpis(self.mpis))
        return bytes(serdat)

def read_packet(dat):
    """Read packet from a bytes-like or memoryview-like object."""
    view = memoryview(dat)
    hb = view[0] # header byte
    if not hb & 0b10000000:
        raise ParseError
    if hb & 0b01000000:
        # New packet format
        tag = hb & 0b00111111
        lenlen, packetlen = parse_length(view[1:])
    else:
        # Old packet format
        tag = (hb & 0b00111100) >> 2
        olen = hb & 0b00000011
        if olen == 0:
            lenlen = 1
        elif olen == 1:
            lenlen = 2
        elif olen == 2:
            lenlen = 4
        else:
            raise ParseError("cannot handle indeterminate length headers")
        lendata = view[1:1+lenlen]
        if len(lendata) != lenlen:
            raise ParseError("truncated")
        packetlen = int.from_bytes(lendata, 'big')
    totallen = 1+lenlen+packetlen
    payload = bytes(view[1+lenlen:totallen])
    return totallen, (tag, payload)

def read_packets(dat):
    view = memoryview(dat)
    tagpaks = []
    while view:
        totallen, tagpak = read_packet(view)
        view = view[totallen:]
        tagpaks.append(tagpak)
    return tagpaks
