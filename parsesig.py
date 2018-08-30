#!/usr/bin/env python3

import hashlib
import attr
import io
import ecdsa
import json

import cashaddr
from minipgp import *

from sigstuff import verifies, compress, sigenc
from bitcoin import minpush, sha256, rip160
import bitcoin

with open('pubkey.gpg', 'rb') as f:
    tagpaks = read_packets(f.read())

pubpak = PubKeyPacketV4.from_bytes(tagpaks[0][1])
assert(pubpak.oid.hex() == '2b8104000a')  ## make sure secp256k1
pubkey = pubpak.mpis[0].to_bytes(65,'big')
cpubkey = compress(pubkey)
assert(len(cpubkey) == 33)

vk = ecdsa.VerifyingKey.from_string(pubkey[1:], curve=ecdsa.SECP256k1, validate_point=True)
print("pubkey.gpg loaded, key ID", pubpak.key_id().hex().upper())



with open('testmsg', 'rb') as f:
    msg = f.read()
with open('testmsg.sig', 'rb') as f:
    _, (tag, sigpak) = read_packet(f.read())
    assert(tag == 2)
spme = SigPacketV4.from_bytes(sigpak)

assert(spme.sigtype == 0) # binary document
assert(spme.pubalgo == 19) # ECDSA
assert(spme.hashalgo == 8) # SHA256

# Calculate full hash
preimage = msg + spme.trailer()
digest = hashlib.sha256(preimage).digest()
hash2 = digest[:2]

assert hash2 == spme.hash2

print("Message:   ", repr(msg))
print("Signature validity on message:   ", verifies(vk, digest, spme.mpis))
print()

# Construct basic redeem script.
OP_CHECKDATASIG = b'\xba'
redeemscript = (  minpush(preimage)
                + minpush(cpubkey)
                + OP_CHECKDATASIG)
# Redeem script hash (for address)
rshash = rip160(sha256(redeemscript))

# Convert signature to bitcoin form.
bcsig = sigenc(spme.mpis[0], spme.mpis[1])
# Calculate ScriptSig
scriptsig = minpush(bcsig) + minpush(redeemscript)

print("Preimage (%d bytes): %s"%(len(preimage), preimage.hex()))
print("Compressed pubkey (33 bytes): %s"%(cpubkey.hex(),))
print("Redeemscript (%d bytes): %s"%(len(redeemscript), redeemscript.hex()))
print("            hash: %s"%(rshash.hex(), ))
print("    ", cashaddr.encode_full('bitcoincash', cashaddr.SCRIPT_TYPE, rshash))
print("        ", cashaddr.encode_full('bchtest', cashaddr.SCRIPT_TYPE, rshash))
print("ScriptSig (%d bytes): %s"%(len(scriptsig), scriptsig.hex()))


# Make transaction
# funding info
inp = dict(prevout_hash  = bytes.fromhex('898e8031163df578acb91931c2da2d0c9ebed6d00b173fd2c1e2556cd5698b11'),
           prevout_n     = 1,
           prevout_value = 30000000,
           scriptsig     = scriptsig,
           sequence      = 0xffffffff,
           )
out = dict(value = 30000000-1000,
           scriptpubkey = b''.join((b'\x76\xa9\x14',
                                    cashaddr.decode('bchtest:qq4j8hh0qac4dy8fe9xyhmtvu9spu9w58unf74hkkd')[2],
                                    b'\x88\xac'))
           )
tx = bitcoin.SimpleTx(1,[inp],[out],0)
print("Transaction:", tx.to_bytes().hex())

