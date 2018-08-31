#!/usr/bin/env python3

import hashlib
import attr
import io
import ecdsa
import json

from minipgp import *
import cashaddr
from sigstuff import verifies, compress, sigenc
from bitcoin import minpush, sha256, rip160
import bitcoin

print("Expecting a secp256k1 key in pubkey.gpg, and minimal cert [pubkey,uid,selfsig,certsig] in bobby.gpg")


with open('pubkey.gpg', 'rb') as f:
    tagpaks = read_packets(f.read())

pubpak = PubKeyPacketV4.from_bytes(tagpaks[0][1])
assert(pubpak.oid.hex() == '2b8104000a')  ## make sure secp256k1
pubkey = pubpak.mpis[0].to_bytes(65,'big')
cpubkey = compress(pubkey)
assert(len(cpubkey) == 33)

vk = ecdsa.VerifyingKey.from_string(pubkey[1:], curve=ecdsa.SECP256k1, validate_point=True)
print("pubkey.gpg loaded, key ID", pubpak.key_id().hex().upper())




with open('bobby.gpg', 'rb') as f:
    tagpaks = read_packets(f.read())

satkey = PubKeyPacketV4.from_bytes(tagpaks[0][1])
satuid = tagpaks[1][1]
# Skip the selfsig packet (2)
satsig = SigPacketV4.from_bytes(tagpaks[3][1]) # our certification sig

print("bobby.gpg loaded, key ID", satkey.key_id().hex().upper())
print("will be signing UID:", satuid)
print(satsig)

assert(satsig.sigtype == 0x10) # generic certification
assert(satsig.pubalgo == 19) # ECDSA
assert(satsig.hashalgo == 8) # SHA256

preimage = (satkey.canonical_packet()
            + b'\xb4' + len(satuid).to_bytes(4,'big') + satuid
            + satsig.trailer())
digest = hashlib.sha256(preimage).digest()

assert(digest[:2] == satsig.hash2) # make sure our preimage matches

print("Signature validity on digest:   ", verifies(vk, digest, satsig.mpis))

print()

# Construct basic redeem script.
OP_CHECKDATASIG = b'\xba'
redeemscript = (  minpush(preimage)
                + minpush(cpubkey)
                + OP_CHECKDATASIG)
# Redeem script hash (for address)
rshash = rip160(sha256(redeemscript))

# Convert signature to bitcoin form.
bcsig = sigenc(*satsig.mpis)
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
inp = dict(prevout_hash  = bytes.fromhex('a546b5e75ac80cf7fe37539cc3282165f72665a3e457d9611edaa6c2d11bc6ae'),
           prevout_n     = 0,
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
