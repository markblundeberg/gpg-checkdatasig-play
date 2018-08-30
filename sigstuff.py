
import ecdsa

def verifies(vk, digest, rs):
    digest = bytes(digest)
    number = int.from_bytes(digest, 'big')

    # According to sec1, we should keep only leftmost bits to match curve.
    extrabits = len(digest)*8 - vk.curve.order.bit_length() # how many more bits in digest
    if extrabits > 0:
        number >>= extrabits

    r,s = rs
    sig = ecdsa.ecdsa.Signature(r,s)
    return vk.pubkey.verifies(number, sig)

def compress(pubkey):
    """ Convert 65 bytes starting with 0x04... to compressed form starting
    with either 0x02 or 0x03.

    http://www.secg.org/sec1-v2.pdf#page=17 for large prime field """
    assert(len(pubkey) == 65 and pubkey[0] == 4)
    x = pubkey[1:33]
    ylast = pubkey[64]
    if ylast & 1:
        return b'\x03' + x
    else:
        return b'\x02' + x

def sigenc(r,s, order=ecdsa.SECP256k1.order):
    """ Put signature into low-S form and DER-encode for bitcoin """
    s = min(s, order-s)
    return ecdsa.util.sigencode_der(r,s,ecdsa.SECP256k1.order)

