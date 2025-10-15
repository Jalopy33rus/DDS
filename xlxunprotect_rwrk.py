#!/usr/bin/env python3
""" Tool for removing IEEE-P1735 vhdl and verilog content protection """
from __future__ import print_function
import sys
import re
import struct
from binascii import b2a_hex, a2b_hex, hexlify, unhexlify
from base64 import b64decode
import zlib
import argparse
import platform

try:
    from Crypto.Cipher import AES, DES
    from Crypto.Util import Counter
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: PyCrypto not available, decryption will be limited", file=sys.stderr)

if platform.python_version() < '3.0':
    from StringIO import StringIO
else:
    from io import StringIO, BytesIO


def uudecode(data):
    """Simple uudecode implementation"""
    try:
        if isinstance(data, str):
            data = data.encode('latin-1')
        decoded = b''
        for line in data.split(b'\n'):
            if line and len(line) > 0:
                try:
                    decoded += a2b_uu(line)
                except:
                    continue
        return decoded
    except Exception as e:
        print(f"UUDecode error: {e}", file=sys.stderr)
        return b''


# Keys dictionary with hex strings - will be converted to bytes
keys = {
    "15": {"key": "93B5313FBB924FC9A57F40CBECE9EA3F41A6916E5BBC4AD8931F003C613BF934", "iv": "1C9C5CFB776F42EC8970FB3918D67B43"},
    "37": {"key": "278D7318A95839DF", "iv": "0D9B9E4FB62AF137"},
    "38": {"key": "F143CB05DA5FE26A", "iv": "0D9B9E4FB62AF137"},
    "50": {"key": "B0E430FB8E024FB4AC0732270D9C3A88", "iv": "2C7F9EEBAE5D40BB8F6BC0B5EF240526"},
    "51": {"key": "8C700049CF544C24A7ABDBC0E896C4D1", "iv": "6D815F2526BAF48AB26519155E45AA49"},
    "60": {"key": "C145AF345F87526C233ADBC875051993A549C46663518B0859E35C1469DDA49D", "iv": "6F4A2505AD8367A4535ECE74D6438EA6"},
    "61": {"key": "2B3B4291844844DEA978A5175A7A8611BA8CFCF39DE54295B778CA7B29A0E537", "iv": "E9029FB591804136B858EFBE07A55729"},
    "62": {"key": "0DE4DDBC43D64F488DC9CE26D5161FA09E0EB0979DD34E4C8E8BB82B71BC9AEB", "iv": "D9A3D631B46BC3AA232219577DA16C48"},
    "64": {"key": "57D2680C0AD24BD38CFC2F0842DA67E5791207B8178042918DD7FC23B284D13A", "iv": "18C9FBCE90144BE997F910FA993FE28F"},
    "65": {"key": "581F4AA947971B02C9B76860BF153E027C0D9257937ABE03853FE928CADC6642", "iv": "4FF0F201813FBEAFA62AACDD88222910"},
    "80": {"key": "030E0F5C4123594F", "iv": "43A25FFF66954813"},
}

# Convert hex values in key dictionary to bytes
for key in keys:
    keys[key]["key"] = unhexlify(keys[key]["key"])
    keys[key]["iv"] = unhexlify(keys[key]["iv"])


class Empty:
    pass


def parseheader(data):
    if not data:
        return None
    if isinstance(data, bytes):
        data = data.decode('latin-1', errors='ignore')
    
    m = re.match(r'^XlxV(\d\d|H[LXY]|c1|D0)([ADE][ABM])([ 0-9a-f]{7}[0-9a-f])([ 0-9a-f]{7}[0-9a-f])$', data)
    if not m:
        return None

    obj = Empty()
    obj.version = m.group(1)
    obj.encoding = m.group(2)
    obj.fullsize = int(m.group(3), 16)
    obj.compsize = int(m.group(4), 16)
    return obj


def strip_padding(data):
    if not data:
        return data
    if isinstance(data, str):
        data = data.encode('latin-1')
    
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def cbcdecrypt(data, keyiv):
    if not CRYPTO_AVAILABLE:
        print("Error: PyCrypto required for decryption", file=sys.stderr)
        return data
    
    if isinstance(data, str):
        data = data.encode('latin-1')
    
    blksize = len(keyiv["iv"])
    keysize = len(keyiv["key"])
    datsize = len(data)

    try:
        if keysize == 8:
            cipher = DES.new(keyiv["key"], DES.MODE_CBC, IV=keyiv["iv"])
        else:
            cipher = AES.new(keyiv["key"], AES.MODE_CBC, IV=keyiv["iv"])
        
        padding = datsize % blksize
        plain = b""
        for o in range(0, datsize - padding, blksize):
            plain += cipher.decrypt(data[o:o + blksize])
        return plain
    except Exception as e:
        print(f"Decryption error: {e}", file=sys.stderr)
        return data


def gethword(data, o):
    """Get 2-byte little endian value"""
    if o + 2 > len(data):
        return 0, o
    value = struct.unpack_from("<H", data, o)[0]
    return value, o + 2


def gethybytes(data, o):
    """Get bytes with length prefix"""
    length, o = gethword(data, o)
    if o + length > len(data):
        return b'', o
    return data[o:o + length], o + length


def getdword(data, o):
    """Get 4-byte little endian value"""
    if o + 4 > len(data):
        return 0, o
    value = struct.unpack_from("<L", data, o)[0]
    return value, o + 4


def getc1bytes(data, o):
    """Get bytes with 4-byte length prefix"""
    length, o = getdword(data, o)
    if o + length > len(data):
        return b'', o
    return data[o:o + length], o + length


# RSA key definitions (simplified for the example)
class RSAKey:
    def __init__(self, m=0, e=0, d=0, name=""):
        self.m = m
        self.e = e
        self.d = d
        self.name = name


# Simplified RSA keys for demonstration
rsa2048 = RSAKey(name="rsa2048-13.1")
rsa3072 = RSAKey(name="rsa3072")

# List of known private keys
privkeys = [rsa2048, rsa3072]


def rsadec(key, x):
    """RSA decryption - simplified for example"""
    if key.d == 0:
        return x
    return pow(x, key.d, key.m)


def getbin(x):
    """Convert bigint to big-endian byte string"""
    hex_str = "%x" % x
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return unhexlify(hex_str)


def unwrap(key, wrapped):
    """RSA-unwrap encrypted key"""
    if not wrapped:
        return None
    
    try:
        if isinstance(wrapped, str):
            wrapped = wrapped.encode('latin-1')
        
        dec = rsadec(key, int(hexlify(wrapped), 16))
        b = getbin(dec)
        
        if len(b) > 1 and b[0] == 0 and b[1] == 2:
            # Remove PKCS#1 1.5 padding
            ix = b.find(b'\x00', 2)
            if ix != -1:
                return b[ix + 1:]
        return b
    except Exception as e:
        print(f"Unwrap error: {e}", file=sys.stderr)
        return None


def decrypt_hy_keys(data):
    """Decode HYbrid key section"""
    o = 0
    key2048, o = gethybytes(data, o)
    count, o = gethword(data, o)
    key3072, o = gethybytes(data, o)
    wrapped_key, o = gethybytes(data, o)
    wrapped_iv, o = gethybytes(data, o)

    key = unwrap(rsa2048, unwrap(rsa3072, wrapped_key))
    iv = unwrap(rsa2048, unwrap(rsa3072, wrapped_iv))

    if o < len(data):
        print(f"HY: left: {hexlify(data[o:])}", file=sys.stderr)

    if key and iv:
        print(f"hy: key={hexlify(key)}, iv={hexlify(iv)}")
        return {"key": key, "iv": iv}
    return None


def decrypt_c1_keys(data):
    """Decode c1 key section"""
    o = 0
    keyname, o = getc1bytes(data, o)
    wrapped_key, o = getc1bytes(data, o)
    wrapped_iv, o = getc1bytes(data, o)

    key = unwrap(rsa2048, wrapped_key)
    iv = unwrap(rsa2048, wrapped_iv)

    if o < len(data):
        print(f"c1: left: {hexlify(data[o:])}", file=sys.stderr)

    if key and iv:
        print(f"c1: key={hexlify(key)}, iv={hexlify(iv)}")
        return {"key": key, "iv": iv}
    return None


def isStubFile(fh):
    fh.seek(0)
    hdr = fh.readline()
    if isinstance(hdr, bytes):
        hdr = hdr.decode('latin-1', errors='ignore')
    return hdr == "XILINX-XDB 0.1 STUB 0.1 ASCII\n"


def isXlxFile(fh):
    fh.seek(0)
    hdr = fh.read(8)
    if isinstance(hdr, bytes):
        hdr = hdr.decode('latin-1', errors='ignore')
    return re.match(r'XlxV(\d\d|H[LXY]|c1|D0)([ADE][ABM])', hdr) is not None


def isBinary(fh):
    fh.seek(0)
    hdr = fh.read(0x18)
    return b'\x00' in hdr


def decodechunk(hdr, data):
    if not data:
        return None

    if hdr.version in keys:
        print(f"enc = {hexlify(data)}")
        print(f"key = {hexlify(keys[hdr.version]['key'])}, iv={hexlify(keys[hdr.version]['iv'])}")
        data = cbcdecrypt(data, keys[hdr.version])
    elif hdr.version == "HY":
        return decrypt_hy_keys(data)
    elif hdr.version == "c1":
        return decrypt_c1_keys(data)
    else:
        print(f"unknown hdr: {hdr.version}")
        return None

    try:
        if data:
            if hdr.encoding == "DM":
                data = b64decode(data)
            
            # Try to decompress
            try:
                decompressor = zlib.decompressobj()
                full = decompressor.decompress(data)
                return full
            except zlib.error:
                # If decompression fails, return data as-is
                return data
    except Exception as e:
        print(f"ERROR {e} in ({len(data)}) {hexlify(data[:16])}", file=sys.stderr)
        return data


def readchunk(fh):
    hdrdata = fh.read(0x18)
    if not hdrdata:
        return None
    
    if isinstance(hdrdata, bytes):
        hdrdata = hdrdata.decode('latin-1', errors='ignore')
    
    hdr = parseheader(hdrdata)
    if not hdr:
        return None
    
    data = fh.read(hdr.compsize)
    return decodechunk(hdr, data)


def readstubhdr(fh):
    state = 0
    while True:
        c = fh.read(1)
        if not c:
            return False
        
        if isinstance(c, bytes):
            c = c.decode('latin-1', errors='ignore')
        
        if state < 3 and c == '#':
            state += 1
        elif state < 3:
            print(f"invalid stub hdr {state} {ord(c):02x}", file=sys.stderr)
            return False
        elif state == 3 and '0' <= c <= '9':
            pass
        elif state == 3 and c == ':':
            return True
        else:
            print(f"invalid stub hdr {state} {ord(c):02x}", file=sys.stderr)
            return False


def getxdmtype(line):
    if isinstance(line, bytes):
        line = line.decode('latin-1', errors='ignore')
    
    m = re.match(r'XILINX-XDM V1\.\d([a-z]*)', line)
    if m:
        return m.group(1)
    return ""


def rledecode(x):
    if isinstance(x, str):
        x = x.encode('latin-1')
    return bytes([x[i] ^ (i & 15) for i in range(len(x))])


def dumpxlx(fh):
    if "HY" in keys:
        del keys["HY"]
    if "c1" in keys:
        del keys["c1"]
    
    hasstubs = False

    if isStubFile(fh):
        secondline = fh.readline()
        hasstubs = True
    else:
        fh.seek(0)
    
    if hasstubs:
        subver = getxdmtype(secondline)
        if subver == "e":
            yield rledecode(fh.read())
            return

    while True:
        if hasstubs:
            if not readstubhdr(fh):
                break
        
        chunk = readchunk(fh)
        if not chunk:
            break
        
        if isinstance(chunk, dict):
            keys["HY"] = chunk
            keys["c1"] = chunk
        else:
            yield chunk


class ProtectParser:
    def __init__(self, args):
        self.verbose = args.verbose
        self.clear()

    def clear(self):
        self.props = {}
        self.keys = []

    @staticmethod
    def pragma_protect(line):
        if isinstance(line, bytes):
            line = line.decode('latin-1', errors='ignore')
        
        m = re.search(r'^\s*(?:`|//|--)(?:pragma\s+)?protect\s+(.*)', line)
        if m:
            return m.group(1)
        return None

    def moveprop(self, k, dst):
        if k in self.props:
            dst[k] = self.props[k]
            del self.props[k]

    def addkey(self, keyblock):
        kprop = {"key_block": keyblock}
        for k in ["key_keyname", "key_keyowner", "key_method", "encoding"]:
            self.moveprop(k, kprop)
        self.keys.append(kprop)

    def adddata(self, datablock):
        if "data_block" in self.props:
            print("prot: multiple data blocks", file=sys.stderr)
        self.props["data_block"] = datablock

    def parsetoken(self, text):
        m = re.match(r'\s+', text)
        if m:
            return m.end(), None, None
        
        m = re.match(r',', text)
        if m:
            return m.end(), None, None

        m = re.match(r'\s*(\w+)\s*=\s*"([^"]*)"', text)
        if m:
            return m.end(), m.group(1), m.group(2)

        m = re.match(r'\s*(\w+)\s*=\s*(\d+)', text)
        if m:
            return m.end(), m.group(1), int(m.group(2))

        m = re.match(r'\s*(\w+)\s*=\s*(\(.*?\))', text)
        if m:
            return m.end(), m.group(1), m.group(2)

        m = re.match(r'\s*(\w+)\s*=\s*(\w+(?:\s\w+)*\.?)$', text)
        if m:
            return m.end(), m.group(1), m.group(2)

        m = re.match(r'\s*(\w+)', text)
        if m:
            return m.end(), m.group(1), True

        print(f"protected: unknown syntax: '{text}'", file=sys.stderr)
        return len(text), None, None

    def parse_properties(self, line):
        o = 0
        while o < len(line):
            r, k, v = self.parsetoken(line[o:])
            o += r
            if k is not None:
                yield k, v

    def process_file(self, fh):
        keyblock = None
        datablock = None
        
        for line in fh:
            if isinstance(line, bytes):
                line = line.decode('latin-1', errors='ignore')
            
            pp = self.pragma_protect(line)
            if pp:
                if keyblock is not None:
                    self.addkey(keyblock)
                    keyblock = None
                elif datablock is not None:
                    self.adddata(datablock)
                    datablock = None

                for k, v in self.parse_properties(pp):
                    self.props[k.lower()] = v

                if "begin_protected" in self.props:
                    del self.props["begin_protected"]
                    self.keys = []
                elif "end_protected" in self.props:
                    del self.props["end_protected"]
                    self.decrypt()
                    self.clear()
                elif "key_block" in self.props:
                    del self.props["key_block"]
                    keyblock = ""
                elif "data_block" in self.props:
                    del self.props["data_block"]
                    datablock = ""
            elif keyblock is not None:
                keyblock += line
            elif datablock is not None:
                datablock += line
            else:
                sys.stdout.write(line)

    def findkey(self, keys, keylen):
        if not CRYPTO_AVAILABLE:
            return None
            
        for k in keys:
            wrapped = self.decode(k.get("encoding", ""), k.get("key_block", ""))
            for privkey in privkeys:
                key = unwrap(privkey, wrapped)
                if key and len(key) == keylen:
                    return (key, privkey.name, k.get("key_keyname", ""), k.get("key_keyowner", ""))
        return None

    def decode(self, encoding, data):
        if not data:
            return b""
        
        if isinstance(data, str):
            data = data.encode('latin-1')
        
        encoding_lower = encoding.lower()
        if "uuencode" in encoding_lower:
            return uudecode(data)
        else:
            try:
                return b64decode(data)
            except:
                return data

    def decrypt(self):
        if not self.props.get("data_block"):
            return

        data_method = self.props.get("data_method", "").lower()
        if "aes256" in data_method:
            keylength = 32
        else:  # aes128 or default
            keylength = 16

        key = self.findkey(self.keys, keylength) if self.keys else None

        if key and CRYPTO_AVAILABLE:
            key_val, privname, keyname, keyowner = key
            data = self.decode(self.props.get("encoding", ""), self.props["data_block"])
            
            if len(data) >= 16:
                plain = cbcdecrypt(data[16:], {"key": key_val, "iv": data[:16]})
                plain = strip_padding(plain)
                
                if plain:
                    sys.stdout.write(f"`pragma begin_decoded privkey=\"{privname}\", key_keyname=\"{keyname}\", key_keyowner=\"{keyowner}\"\n")
                    if not args.nodata:
                        try:
                            sys.stdout.write(plain.decode('latin-1', errors='replace'))
                        except:
                            sys.stdout.write(str(plain))
                    else:
                        if len(plain) <= 20:
                            sys.stdout.write(f"** {len(plain)} bytes: {hexlify(plain)}")
                        else:
                            sys.stdout.write(f"** {len(plain)} bytes: {hexlify(plain[:8])} ... {hexlify(plain[-8:])}")
                    sys.stdout.write("\n`pragma end_decoded\n")
        else:
            descriptions = [f"{k.get('key_keyowner', '')}:{k.get('key_keyname', '')}" for k in self.keys]
            sys.stdout.write(f"`pragma protect: no known key found: {', '.join(descriptions)}\n")


def process_protect(fh, args):
    parser = ProtectParser(args)
    parser.process_file(fh)


def main():
    parser = argparse.ArgumentParser(description='Tool for decoding protected VHDL/Verilog files')
    parser.add_argument('--verbose', '-v', action='store_true', help='print info for each key')
    parser.add_argument('--nodata', '-n', action='store_true', help='omit the decrypted data')
    parser.add_argument('files', type=str, metavar='FILE', nargs='*', help='a protected data file')
    
    args = parser.parse_args()

    if not args.files or (len(args.files) == 1 and args.files[0] == '-'):
        process_protect(sys.stdin, args)
    else:
        for fn in args.files:
            if len(args.files) > 1:
                print(f"==> {fn} <==")
            
            try:
                with open(fn, "rb") as fh:
                    if isBinary(fh):
                        print(f"Binary file detected: {fn}")
                    elif isXlxFile(fh) or isStubFile(fh):
                        for chunk in dumpxlx(fh):
                            if isinstance(chunk, bytes):
                                try:
                                    sys.stdout.write(chunk.decode('latin-1', errors='replace'))
                                except:
                                    sys.stdout.buffer.write(chunk)
                            else:
                                sys.stdout.write(str(chunk))
                    else:
                        fh.seek(0)
                        process_protect(fh, args)
            except Exception as e:
                print(f"Error processing {fn}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
