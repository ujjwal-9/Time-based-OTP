import hmac
import hashlib
import time
import sys
import struct

shared_secret = str(raw_input("Enter Shared Secret Key : "))
pass_len = int(input("Enter Pass Length : "))

"""HyperParameters :)"""
timestep = 30
T0 = 0

def HOTP(K, C, digits=10):
    """HTOP:
    K is the shared key
    C is the counter value
    digits control the response length
    """
    K_bytes = K.encode()
    C_bytes = struct.pack(">Q", C)
    hmac_sha512 = hmac.new(key = K_bytes, msg=C_bytes, digestmod=hashlib.sha512).hexdigest()
    return Truncate(hmac_sha512)[-digits:]

def Truncate(hmac_sha512):
    """truncate sha512 value"""
    offset = int(hmac_sha512[-1], 16)
    binary = int(hmac_sha512[(offset *2):((offset*2)+8)], 16) & 0x7FFFFFFF
    return str(binary)

def TOTP(K, digits=10, timeref = 0, timestep = 30):
    """TOTP, time-based variant of HOTP
    digits control the response length
    the C in HOTP is replaced by ( (currentTime - timeref) / timestep )
    """
    C = int ( time.time() - timeref ) // timestep
    return HOTP(K, C, digits = digits)

passwd = TOTP(shared_secret, pass_len, T0, timestep).zfill(10)
print passwd
