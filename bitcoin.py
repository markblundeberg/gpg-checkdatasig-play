"""
Minimal bitcoin cash transaction stuff for making weird smart contracts
"""
from collections import namedtuple
import struct
import hashlib
from itertools import chain

### Transactions stuff

zero32 = b'\0'*32

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_FORKID = 0x40
SIGHASH_ANYONECANPAY = 0x80

default_hashtype = SIGHASH_ALL|SIGHASH_FORKID

def sha256(b):
    return hashlib.sha256(b).digest()

def rip160(b):
    ripemd = hashlib.new('ripemd160')
    ripemd.update(b)
    return ripemd.digest()

def hash160(b):
    return rip160(sha256(b))
def hash256(b):
    return sha256(sha256(b))


# Convert python int to 1,2,4,8-byte little endian unsigned integers.
# Input range is checked.
# These are the fastest way I know of (better than calling bytes() or using int.to_bytes).
int_to_ubyte = struct.Struct('B').pack
int_to_ule2  = struct.Struct('<H').pack
int_to_ule4  = struct.Struct('<L').pack
int_to_ule8  = struct.Struct('<Q').pack

# These functions take in bytes, offset and return (integer, new_offset)
def structreader1(format):
    s = struct.Struct(format)
    slen = s.size
    sunp = s.unpack_from
    del s, format
    def fun(b, offset):
        data, = sunp(b, offset)
        return data, offset+slen
    return fun
read_ubyte = structreader1( 'B')
read_ule2  = structreader1('<H')
read_ule4  = structreader1('<L')
read_ule8  = structreader1('<Q')

def read_nbytes(b, n, offset):
    new_offset = offset+n
    res = bytes(b[offset : new_offset])
    if len(res) != n:
        raise struct.error("too few bytes")
    return res, new_offset


def var_int(i):
    """Return bytes representation of bitcoin's variable length integers.
    They are sometimes used for counters, sometimes used for byte lengths.

    https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    """
    i = int(i)
    if i<0xfd:
        return bytes((i,))
    elif i<=0xffff:
        return b"\xfd"+int_to_ule2(i)
    elif i<=0xffffffff:
        return b"\xfe"+int_to_ule4(i)
    else:
        return b"\xff"+int_to_ule8(i)

def read_var_int(mv, offset):
    """ Read var_int from offset and return new offset. """
    b0 = mv[offset]
    if b0 < 0xfd:
        return b0, offset+1
    elif b0 == 0xfd:
        return read_ule2(mv, offset+1)
    elif b0 == 0xfe:
        return read_ule4(mv, offset+1)
    elif b0 == 0xff:
        return read_ule8(mv, offset+1)




class SimpleTx:
    """ A lower-level bitcoin transaction ser/des.

    This only uses bytes objects. It does not ever parse scripts, so
    you can use all manner of weird scripts.

    You can correctly calculate the preimages used in OP_CHECKSIG, for
    any hashtype (SIGHASH ALL/NONE/SINGLE and/or ANYONECANPAY).

    All `inputs` elements are dicts with 'prevout_hash' (bytes len 32),
    'prevout_n' (int), 'prevout_value' (int), 'scriptsig' (bytes),
    'sequence' (int).

    'prevout_value' and 'scriptsig' are semi-optional, being needed by
    different member functions.

    All `outputs` elements are dicts with 'value' (int) and 'scriptpubkey' (bytes).
    """
    forkid = 0x000000

    def __init__(self, version,inputs,outputs,locktime):
        self.version  = int(version)
        self.inputs   = inputs
        self.outputs  = outputs
        self.locktime = locktime
        self.digest_cache = {}

    @classmethod
    def from_bytes(cls, raw, error_extra=True):
        raw = bytes(raw)
        mv = memoryview(raw)

        offset = 0
        version, offset = read_ule4(mv, offset)

        ninputs, offset = read_var_int(mv, offset)
        if ninputs*37 > len(raw)-offset: # sanity check in case ninputs is 4 billion
            raise struct.error('Number of inputs too large')
        inputs = [None]*ninputs
        for i in range(ninputs):
            ph, offset = read_nbytes(mv, 32, offset)
            pn, offset = read_ule4(mv, offset)
            scriptlen, offset = read_var_int(mv, offset)
            script, offset = read_nbytes(mv, scriptlen, offset)
            sequence, offset = read_ule4(mv, offset)
            inputs[i] = dict(prevout_hash=ph[::-1], prevout_n = pn, scriptsig=script, sequence=sequence)

        noutputs, offset = read_var_int(mv, offset)
        if noutputs*5 > len(raw)-offset: # sanity check in case noutputs is 4 billion
            raise struct.error('Number of outputs too large')
        outputs = [None]*noutputs
        for i in range(noutputs):
            value, offset = read_ule8(mv, offset)
            scriptlen, offset = read_var_int(mv, offset)
            script, offset = read_nbytes(mv, scriptlen, offset)
            outputs[i] = dict(value=value, scriptpubkey=script)

        locktime, offset = read_ule4(mv,offset)

        if error_extra and len(mv) > offset:
            raise ValueError("extra bytes found after transaction")

        self = cls(version,inputs,outputs,locktime)
        self.raw = bytes(mv[:offset]) # Save the raw bytes up to this offset.
        return self

    def to_bytes(self,):
        """ Returns byte serialized transaction as appropriate for broadcast.
        (note that most broadcasting APIs expect hex)

        If scriptsig is missing on any inputs this will fail.
        """
        return b''.join(self.serialize_parts())

    def digestInput(self, i, nhashtype, scriptcode):
        """
        Return the 32-byte digest for a given input, in given sighash mode.
        You need this to create/verify CHECKSIG signatures.

        The specified input (by index `i`) must have a 'prevout_value' entry.
        It does *not* need a scriptsig.

        nhashtype is an integer 0-255.
        This is bitcoin cash so you must include SIGHASH_FORKID.

        `scriptcode` needs to be provided. It is defined as the currently
        executing script taken from the last OP_CODESEPARATOR, if present.
        For P2SH, 'currently executing script' is defined as the redeemscript.

        Important: The digestInput result generally depends on the other
        inputs and outputs, except for special cases of nhashtype. Make sure
        you do not call it before you settle these things.
        """
        # Following this procedure:
        # https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/replay-protected-sighash.md

        i = int(i)
        nhashtype = int(nhashtype)
        scriptcode = bytes(scriptcode)

        cache = self.digest_cache

        cache_id = (i, nhashtype, scriptcode)
        try:
            return cache[cache_id]
        except KeyError:
            pass

        self.inputs = tuple(self.inputs)
        self.outputs = tuple(self.outputs)

        inp = self.inputs[i]
        try:
            value = inp['prevout_value']
        except KeyError:
            raise ValueError("Missing prevout_value -- cannot digest.", inp)

        assert 0 <= nhashtype <= 0xff
        if not nhashtype | SIGHASH_FORKID:
            raise ValueError("Missing SIGHASH_FORKID. Digest in non-forkid mode not implemented!")
        basetype = nhashtype | 0x1f

        if nhashtype | SIGHASH_ANYONECANPAY:
            hashPrevouts = zero32
            hashSequence = zero32
        else:
            try:
                hashPrevouts = cache['hashPrevouts']
            except KeyError:
                hashPrevouts = cache['hashPrevouts'] = self.hashPrevouts()
            if basetype != SIGHASH_NONE and basetype != SIGHASH_SINGLE:
                try:
                    hashSequence = cache['hashSequence']
                except KeyError:
                    hashSequence = cache['hashSequence'] = self.hashSequence()
        if basetype != SIGHASH_NONE and basetype != SIGHASH_SINGLE:
            try:
                hashOutputs = cache['hashOutputs']
            except KeyError:
                hashOutputs = cache['hashOutputs'] = self.hashOutputs()
        elif basetype == SIGHASH_SINGLE and i < len(self.outputs):
            hashOutputs = hash256(b''.join(serialize_output(self.outputs[i])))
        else:
            hashOutputs = zero32

        digest = hash256(b''.join(
            int_to_ule4(self.version),
            hashPrevouts,
            hashSequence,
            inp['prevout_hash'],
            inp['prevout_n'],
            var_int(scriptcode),
            scriptcode,
            int_to_ule8(value),
            int_to_ule4(inp['sequence']),
            hashOutputs,
            int_to_ule4(self.locktime),
            int_to_ule4(nhashtype | (self.forkid << 8)),
            ))

        cache[cache_id] = digest
        return digest

    def signInput(self, i, nhashtype, private_key):
        """ Signs transaction using the given private key, as appropriate for
        using in OP_CHECKSIG.

        Returns the ~71 byte DER signature in low S form. This
        does not make scriptsig however -- that is up to you!
        """

    def hashPrevouts(self,):
        flatten = chain.from_iterable
        return hash256(b''.join(flatten(
                    (inp['prevout_hash'], int_to_ule4(inp['prevout_n'])) for inp in self.inputs
                    )))
    def hashSequence(self,):
        return hash256(b''.join(
                    int_to_ule4(inp['sequence']) for inp in self.inputs)
                    )
    def hashOutputs(self,):
        flatten = chain.from_iterable
        return hash256(b''.join(flatten(
                    serialize_output(out) for out in self.outputs
                    )))


    @staticmethod
    def serialize_parts_input(inp):
        """Returns five bytes objects"""
        scriptsig = inp['scriptsig']
        return (inp['prevout_hash'][::-1],
                int_to_ule4(inp['prevout_n']),
                var_int(len(scriptsig)),
                scriptsig,
                int_to_ule4(inp['sequence']),
                )

    @staticmethod
    def serialize_parts_output(out):
        """Returns three bytes objects"""
        outscript = out['scriptpubkey']
        return (int_to_ule8(out['value']),
                var_int(len(outscript)),
                outscript
                )

    def serialize_parts(self,):
        """Like serialize but returns all pieces in tuples."""
        flatten = chain.from_iterable
        return chain(
                    (int_to_ule4(self.version), var_int(len(self.inputs)), ),
                    flatten(self.serialize_parts_input(inp) for inp in self.inputs),
                    (var_int(len(self.outputs)), ),
                    flatten(self.serialize_parts_output(out) for out in self.outputs),
                    (int_to_ule4(self.locktime), ),
                    )


### Script helpers

def minpush(b):
    """ Return minimal push form for bytes `b` in bitcoin script."""
    l = len(b)
    if l == 0:
        return b'\x00'
    elif l == 1:
        if b[0] == 0x81:  # 0x81 is pushed by OP_1NEGATE
            return b'\x4f'
        elif 0 < b[0] <= 16:
            return int_to_ubyte(80 + b[0])
        return b'\x01' + b
    elif l < 0x4c:
        return int_to_ubyte(l) + b
    elif l <= 0xff:
        return b'\x4d' + int_to_ubyte(l) + b
    elif l <= 0xffff:
        return b'\x4d' + int_to_ule2(l) + b
    else:
        return b'\x4e' + int_to_ule4(l) + b

