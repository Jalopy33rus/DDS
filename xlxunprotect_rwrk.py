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
    # "16"
    # "17"
    # "1Y"

    # 32DB, 33EB, 34EB, 35EB, 36EB, 37EB, 37DB

    # 30
    #  .. these keys are in the binary, but don't seem to be used.
    # "32":{"key":"886592C2B46F3CD6", "iv":"E78437FD7C4503F3"},
    # "33":{"key":"7EB0C67E6B9B81E4", "iv":"FB744BDFFBAEE2B6"},
    # "34":{"key":"2990DC694EF16DC9", "iv":"567DFFD0706FE1AB"},
    # "35":{"key":"94FED660DE79DD61", "iv":"BFA101DDDECD319A"},
    # "36":{"key":"1CF07C2287EBE145", "iv":"7284567847970F9F"},
     "37":{"key":"278D7318A95839DF", "iv":"0D9B9E4FB62AF137"},
    #   9E5C257AF9954B05 F6D554BCDFF4BD32

    # 38EB
    "38": {"key": "F143CB05DA5FE26A", "iv": "0D9B9E4FB62AF137"},
    # 43
    "50": {"key": "B0E430FB8E024FB4AC0732270D9C3A88", "iv": "2C7F9EEBAE5D40BB8F6BC0B5EF240526"},
    "51": {"key": "8C700049CF544C24A7ABDBC0E896C4D1", "iv": "6D815F2526BAF48AB26519155E45AA49"},
    "60": {"key": "C145AF345F87526C233ADBC875051993A549C46663518B0859E35C1469DDA49D", "iv": "6F4A2505AD8367A4535ECE74D6438EA6"},
    "61": {"key": "2B3B4291844844DEA978A5175A7A8611BA8CFCF39DE54295B778CA7B29A0E537", "iv": "E9029FB591804136B858EFBE07A55729"},
    "62": {"key": "0DE4DDBC43D64F488DC9CE26D5161FA09E0EB0979DD34E4C8E8BB82B71BC9AEB", "iv": "D9A3D631B46BC3AA232219577DA16C48"},
    "64": {"key": "57D2680C0AD24BD38CFC2F0842DA67E5791207B8178042918DD7FC23B284D13A", "iv": "18C9FBCE90144BE997F910FA993FE28F"},
    "65": {"key": "581F4AA947971B02C9B76860BF153E027C0D9257937ABE03853FE928CADC6642", "iv": "4FF0F201813FBEAFA62AACDD88222910"},
    "80": {"key": "030E0F5C4123594F",                "iv": "43A25FFF66954813"},

    # "H1"
    # "HY"   -- keys are encoded in the header.

    # these formats i have not yet decoded:
    # "HL"
    # "c1"

    # "D0"  - 'debug'
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


# RSA key definitions
class RSAKey:
    def __init__(self, m=0, e=0, d=0, name=""):
        self.m = m
        self.e = e
        self.d = d
        self.name = name


# ISE 13.1 key ( april 2011 )
rsa2048 = RSAKey()
rsa2048.m = 0xdfe6242b11772ce803207e33111ff538ddd08b46078cba394305fe7311eeb13291d7043078ba06e95ace0b379d5b52cf6874ff3aea61a462a00879189b1f9e9bbe8f7d622b89aad1e916fdf4c41e99b690e3d15d1feb4d10cddefe10a055f9899afc88f819fb44d33a5954ed45cf90ac27f16deed6159c8465840ff0a3f2e3624f3ddf4d3558111afc450cbb447a01417bc84d83f52bb2aa91229746dd0b390d831fd822578e6b28539f66c1771caa13cb2694b704648c232c6525b04e270c04ed149a35cbb4b74882cd0f2cd147f1181f65d9e260f65188dbd5a77cb07837917565c211e5ce0418066e628cc6b079e298085aa7c37ed0f22726b1e1964edb81
rsa2048.e = 0x03
rsa2048.d = 0x9544181cb64f7345576afeccb6154e25e935b22eafb326d0d759544cb69f20cc613a02cafb26af463c895ccfbe3ce1df9af8aa2746ebc2ec6ab050bb12151467d45fa8ec1d0671e1460f53f882bf11246097e0e8bff23360893f540b158ea65bbca85b5011522de226e6389e2e8a6072c54b9e9f3963bdad9902b54b17f742404ae9ef667880e3c5cc1860313a7f595994d905e018efd0a4e65999fbac9f8edef836c7acbfc2effd2a385f92b13c959bbe731fc19013619a33497a73c671867cff08c721973c1d003f9ef3062a13e3c0940096b9dde97c21de370e7eb2701ddc4b39ab1f812ae82e3eb53153c59478acadb20583e85ea3e8814fac9feb473003
rsa2048.name = "rsa2048-13.1"

# ISE 14.7
rsa_2013_09 = RSAKey()
rsa_2013_09.m = 0xe8bc1330745b231c3f0268eaf8cd0eaacadb06f79b4129b4ae15841230f886a604cb574c3e0b523357ea5b5b48824854798c1d494511c4c5d36c149d1b83a666b9ea1f08273683af7858c9a4d2ad90fa2d292f9c98ea50ef6eaefd513845d678051e3e3220b372faeaaf249330fd184ee7c6019eeea6e0865e513b3468518008a13e8de2af74c3093eeff17a12c8f7e4bf95ae9e8c6ac147a686d2d10f16f6a76ae10a30c416de87765260937dce94d6af7cad3c590ad60f7bb600573fbd255d553d4ff9c861654ede488fd25fadc30ef68d1b38de653b59a53fdddce048de9a9378d64f2d23b9c582b55a4f2481ef92de4ebc77ee6fb83dfef7ff253a0d4b9b
rsa_2013_09.e = 0x10001
rsa_2013_09.d = 0x3bfd86c0bdad644e7a9b6769f1fa0166dae53c5584ca7632a190e03b442e3b9efdab607441a5ef6956a70d27697853a69ab2183673bc51c9606702a5409b5dc02afa0347b9bbde93d364a78d79d4cd82ff331797b8fee51fe29aeea709e74e921f579d5694814d090a875cd9280e853e8995cb83292710c6f1f6e458eceedd1e5e76a195534332877caab0dfb941d58392176608868acc46090359c87bc5354f31bc104a2fddcc631d2d175f0c1535e78d075daaed2ba72dc59df67d538b8d33211671a4e21538d52115b6d9e57544209dc362533fb897bb9931a6c0c20291a009079f6864921fea57ff7cd0528844b574bd98c65e23d927a622d22e917e2a19
rsa_2013_09.name = "rsa2013-09-14.7"

# either nov 2014, or vivado 2014.1 ??
rsa_2014_03 = RSAKey()
rsa_2014_03.m = 0xb31bb84c5138a0f8c01cad9202f41f851d2b1925a5cc366afedcc327d3d68ae559e3aa92226898b6ecd6d785570625cb57ad608db133ad834c4bf38e7ca51fce3f3e1b6e4d59349f8a4523874d8a5c800c2e652c66661525c5b9a0bc8eaf183d2304c4ac0c0539d29f7462de788ea5772ce743cd8e8a7979a6210e1e28b3c2c4c3211b48ac1cae49f89597ba7f42c924aa987664683cedd2e9945798cdcbcee1106c1d7728673394989eb195fbe026a60c472f9c8b780573f7c3f2a39895d906ffbcf17d10d855bd2946e3736926174db5ffa8a76c3b92d8548bfc2bf9ae4e49301f3e58d8a53a77fccefbcaeaa29db684623b17484abb57005965806bf68d03
rsa_2014_03.e = 0x10001
rsa_2014_03.d = 0xacd3f7bfb4b427284100ab3ff497aa7ea149c02742d84e3e6a958dbf35bb952580da9df20b3fd0f4da8ee942a259ad488cdf210738d17c01f1326cdfb64903ead9bdcd6c5f38cffd8ec7ee63962007e80b590d898d79bdb848163a1318bfbe6ce808a6dab972a57c271f8073d9f313996efbedc241643f997203fd827e960f3e7e7fd97c70a8902db90435e1e31a9c8d8a726b013857435adaaa0e9fe74c2974798b3a1abf37dbf07d1dac14778954e707cfb22a6becb55cfd933fac4e8ba8c123a2f6b6e9a9d736a3b520280381f3904897b6f82e1f48bd3e3a0af87c45635776b6f8f5df5547eb84f4a8dcbcde730380c5f1f7c6c11e031e50931faff920a9
rsa_2014_03.name = "rsa2014-03"

rsa_2015_12 = RSAKey()
rsa_2015_12.m = 0xbcc59e729c21f56d17ceb0cd2db2cc5e1be3be276bfb87bea42c0cca6c2cb152eb8420b93231d10e8e085276081dd399b4c485bb4571c94690771122bfc9136d20cc839d2349142f66cd10bd3b3a3af4b26042872febff75cb3d5cee0c6591c26a8b00a27d552b60fe47ebc0ee0fec75a0b2bc53feb8571f19c155570b5f4c6f8e3f38852f807d21f7338d3cd91408cacde161e85130745779c4e5a7c29d212175d5aea69394df61870f64b56c10f962c18211bbdbd6e5232a91ef0d4d9f1cc44930d249c3575079986369b656d7fe7bfb3324bd4f8c035c1701ad0616d01e661abfb35d89b18c1a9f73f4f42080417fb1496f927039485321bcb2129c8c7dd1
rsa_2015_12.e = 0x10001
rsa_2015_12.d = 0x9ff07412391550a330e3afcaf7e820ddaf95a35c3552752de25d6c2ce9c0683190586f7d59f8f95ef29a3c7bc2deba94e5a30887a60c0574231caec919639d70fdb429e32ead514be436e4f2dfc6b382f5cb3732e1387c466a7fc047f4faeda7a2abc94ae314115fe9b2381e4bd5f40ba9af267fa836b9a221293c4c36d774a32f1bf3f2425a6d5e0714f962b7e2679d9df0ea89eaf4b5a9183151087faf4340cb390a809401f281c7eff9754547c2ad2421f5fa6701c8a4ff9a81abbc3920b7a09e83cd972aaf9c2b6169b70e76106556ed6a4a895204d26ca49e0a03b85716132ad48c6492459cb7550fdbace65546dd493f922e61b0f44e806bd6999d4401
rsa_2015_12.name = "rsa2015-12"

rsa_2016_05 = RSAKey()
rsa_2016_05.m = 0xc5984d9a8d6570aa4b60f038bd7548b21863f70aae3ff8eac0d2b65d015890ea24a37bbb715bac115e74d12643912739a16ed727ac46eddb65ad0ba1e63c9535a2abc95785a305dfd8b4d1b5e6e84351ecac244809da51faac94f49060f25452ecb85aa89ab4af511e149e96f31a1f8a8f60804bdd5af3c61a966ed21bff7f292e4567af0c20b9213731d8678778710aa44b2aa8118c50e132bfe31145dce9a5a900225741d8c4467f6089a82d8ba6d71dc6bcb43d00d01e60acad08bb5710c674f429f62abe7baafec174aa25beebcb315c1d7208e0de0895a66c0689802c2567b01c4bcb1d6294a597b1dc0e487d081f51234cb22ac52c76a4905f90546bc5
rsa_2016_05.e = 0x10001
rsa_2016_05.d = 0xb47b51deea6a0e87adc444873f1e22a171bfd5456f35c591ff40380c298f91061d232a8062a15e409b2b4e6289f2ca864c5ae6b1391dac62eab32dddda63d9d21cdc96529820f8dba6a03ab0d0d1b3b3dfdeb8610886debc7de8ac9e37bf00a0a1d21e14c50266e44bfa7f84d756341b26acf962d2342257ffaf0a5865f4705b3d26dacc97be1f9099db659281dc730fd036089da72955e8189c7c25ef8241538d51b5571d0be3a995a4cb3f975ca40c0b7e0d3cd09bcf4c4d73606e4fae88cdf730b17f2b8890278da7e4f04373c2ffd3da49f9258e25021697a349bc8ae0462c7734778e4e63ee20b47040c794961e253d094c9722ba9dba65afe3a6981b5d
rsa_2016_05.name = "xilinx_2016_05"

rsa3072 = RSAKey()
rsa3072.m = 0xe0e2d4d1dad44fc898a15af4d42b6ee1139f4d1a987b61c0fd088859743a3750c9056a188f79370c75e6c8e9149d94efee0b5ac3f9674d22fbc4c20d8cd22de48051282fc428335623df0afde048550de985c3792903e978abb7d71caccc5117915fb85c09c00a242f010c51a12dc6cd93ede18fd80e5bbbc30a7a34ec44cb09f41debdf1c61d00dc9d5ce15a2c5a33d52a235b344c642d1b10bba08b138b93cb9fe76b0dbd266ed680a4e92774383ca8569db443bc7e0e4df051a23ee746fae579c7bbf6ca7b8ef8018a9122d7c10688ad4efe399a32c72008f7ce9ce6478993d3550f703331a21006c4676e9b7ebe8e61bee2df30c7246cef4c5454aace788dad45f7d9aeda1064d936074e629b54354b3b38de27f64eadfe4d14eaf9b12c39f0b2c2ccbac976930a998476bebc21d9425d8115894a9dfaab6893bb415175049099721f243ab24727d19d80451303372491e95a4328b5650f483fdad51cdc9c91ca785fc12020a313bf1c1f6fe27a14b4b670f7085089d6fe6da71897964a1
rsa3072.e = 0x03
rsa3072.d = 0x95ec8de13c8d8a85bb163ca3381cf4960d14de11bafcebd5fe05b03ba2d17a35db58f165b4fb7a084e99db460dbe634a9eb23c82a644de1752832c09088c1e98558b701fd81acce417ea0753eadae35e9bae8250c6029ba5c7cfe4bdc888360fb63fd03d5bd55c181f5608366b73d9de629e965fe55ee7d28206fc23482ddcb14d6947ea12ebe0093139340e6c83c228e1c179222dd981e120b27c05cb7b26287bfef9cb3d36ef48f006df0c4f8257dc58f13cd827da95edea0366c29ef84a72fa796d7c9d4d4506e8acafb113c9b39823f355cd9c16ff4815aa2a68f8ff0c2e95cd910120b1e2af251d3c9967e765f5575b1b6304269aede57ea49025f88a367989fd7f2a89d8d01bf8b485b0bfe08cac720d6857c4db6eeb0ac5cfa68c6780a4df161a6ba1e6215cc1a3034768ef022505b1d2faca87f812ac71a7cead15f5ab7f8a4e9d55e3a02e2eebe3bb4293a528cc91976d6b50122460d529dae8397ef05288bd86043ed6902a50bfb15ab2af6dd44b7ffdade4b2f76646e7223513cb
rsa3072.name = "rsa3072"

rsa_2017_01 = RSAKey()
rsa_2017_01.m=0xbb7f187db03c238267c2e0d59c3526993770f2809cf9c34fc8b46ca64b9e4f19addb17b1bae08cf876bb220a6eb505ed8f12c4e4957eb96daa252b9a85e71f83c5c01bb9a02c0a3afe1b8c79afe6f6030311b7ff3e236e335948dfb292ed020b4fa3d754d880764c610c34d3aae3360de6baae7dc90ab0e4a2a6dff166bc5df6628194337211f49f30afb725994ca4c5dccee1e8647c274fbf60523c2491baa746f0cb0d1aaa05c2238eda64eb7c3ea20e96617107b29c312baafe0cf1289f995603303b3ccdd45eae4005bea964022e5267a56c7af76d49246f0fc3e5ba3c22d967cbb92ef83ba6652ac19e405671e4ea29545994f2badcc9f55699e12ff8c1
rsa_2017_01.e=0x10001
rsa_2017_01.d=0x2c6843c2b114ed4c1b8b3a791d50315e249569ba3073af609c26af7d0b77e94029bf347371d17151ffbcfea8fde37e0defcf00372b79222de91878a55685911f429ce774258d88b6c42c7e2eec0c85c3dcdc3b7a069b99a42bc768c400ac85c96c09601cc65256b26c61d9b93046342d42b28055666253d732f6d71f73b7b58117b6eea44c99a266fa2b0a46ef7e9e6449618643348155d8a7ac53273df4dbfaba5b676568782793db8b739979f745f20de030eb9c2a200c78f1df65f543fc75f7381a0a0d75d4784092fec5a68728d8ad80f6865c9615094f24e63a467f1acdf0242012086edffad38662aafdd3521ab5088b93c001b49352cf3329cd0f3661
rsa_2017_01.name = "rsa_2017_01"

rsa_hybrid1 = RSAKey()
rsa_hybrid1.m = 0xd8239eeba1b99d75422a086a36aa45639d61c47c3756698845f26cafb864a22a2c010a32b3eb0ac48001e917571d5b88c6bbf118267a3f19cfea1e703e25c0cd169ac1194d005d5f311eba2c0af8da5c8a134b
rsa_hybrid1.e = 0x10001
rsa_hybrid1.name = "xilinx_hybrid1"

rsa_hybrid1_3k = RSAKey()
rsa_hybrid1_3k.m = 0xd29aba904bb74fe1c3fde98b1ae20e3f31be851744265a0a614625bb98bc203d32647d2c730fac7f759427a712007418bc2b7775310d36b0b883816e49695ab621c69873c8e365d384f5ab70e4c3694c4b68b1292abe5981f3034a05fc0a88f35eaae24439a3a88ae9851ef0487df069377a308ed6fd79e85fb6f25c54b2e8cd9dc7886dbb2d2b3e00a52ad8484e2ffa6b0e2566bc3960293df5cacca2f829e1e882704815cc2c1ed5294bf82f5d24db5e46413a2e3b4fe4c6eca4cc5bc9777073220a37c687a47a9c3a8d61545456af54b09a21836ac5310b7407c4f88efb846725690be2fb41e036ee6567328c5ba3835ea75b6805df5fc08cbb014c2b17d1e49a703520fab15e9f31942fb7b34444f04182afb886d0bfb057900c1024ea271834a90f9a6fe9136b6523d4cd967ea889e83583c0c3e451c5d201d0c3f589ae5f0c71300b02f624c6265db96eb907ec7fa8f826a7391e7bc9127c2425766fa252660bcb7d2f6ed0c90e43912394cfa34f816e711b35a04c9f9cc67789955ba3
rsa_hybrid1_3k.e = 0x10001
rsa_hybrid1_3k.d = 0x39061e37cdd88faf9092e2b6808beed19b957b91e629003e4942661b1a6aedcbc426436252b14ec2a042824e1168c006a6849a6ec7de4d0da29830e67cc82300a7ba8f32e294f7d042f305fda66366d27aa4993b8d50470a1193b56a536942d5aaaf585ea2c0b6750e6fb605d78b0a1a6324199bc38894869fcbf86999a16bb9a8dc0b0bb31fb2d2b1f806d6d31520968c80230e632ea1e3e8dbf192611a12b51170a8184c96a0e7a44def3cff0e1859b17812573f875dc5933b261013564499573a50d53255a2822bc31032aa5c9261e4fdfd30c82398ad377bb8bd66a416de2bcec91326b54d02f990f6134cf7bda30863872d14f64878019d94be65587a258b9b2a2ea4f7032379becd1cdbd74751ddf932e7566cee3e75b3d90228d2cb1a3090a6451b1340f399dc618851f531c98d53d6e8a7cc3eb8376c2039f8c2f5b3e7a7d8c32f5d517bafa9bc6b5ae28b2194aebe0f7292e556fb9f9931c8c484785abab1b555f29083c0d59af724a52c0fa97925b7f6ccaab6b90a4342e5763031
rsa_hybrid1_3k.name = "xilinx_hybrid1_3k"

rsa_2016_09 = RSAKey()
rsa_2016_09.m = 0xd8239eeba1b99d75422a086a36aa45639d61c47c3756698845f26cafb864a22a2c010a32b3eb0ac48001e917571d5b88c6bbf118267a3f19cfea1e703e25c0cd169ac1194d005d5f311eba2c0af8da5c8a134b9eeee0a49029c7a5b2a939ec857ef2cb500570079b46c77b212fdfea82f842c1d06b943b6dba67e53ab68a3c1183001896e7920b0f2a816d8860d2f0468edf957de6fabccf444e3f6b18942de8638d15744f4ba71a7cace6d14055ff7fe63ac40bfb89f7c7fea009b4507b5502ec559642940feedd0b2144808edb146b3c9fd356e22acd669c875f3b40075e1acb140ed6c4819a44cac68817ff705d45e53c5c7bfc4b0c0b0da5e33e7d5d29a3
rsa_2016_09.e = 0x10001
rsa_2016_09.d = 0x7332b91739c1668d02d0c85f63f768b8693f9cabe00aac80b757385a87db0b1b930c92d4e754150f1a72ea3b48711b42513a068c2aa5e94fe6a30fca1f359c07334f143059fc21c804b42de21f8ef7436f4c4d77ce35e93ff524b5c9fdac23c61b1d6903a3824c6b9453e9ea8c4bba004835bc7b4b7b5c1965cace4076de4298cf8a0a8f8980086eece9329162434473914658ec18ff7e4cac18269ccf7f4cb055bd4109e844b925034c4a8e6ecf1e36e6e5314d90909887ffaef6f69eaed33b236ca739cb9a074b3618eea66bbbe8f8ed00af750882ff74070f6746beb4652c7b2cee08f14bb16ebef28cbf41312410a9a1d352708ca5086deeef08d6d10531
rsa_2016_09.name = "xilinx_2016_09"

# altera - MGC-DVT-MTI
alterakey = RSAKey()
alterakey.m = 0xb7f12cd1f2eeb1c3530a44340fad93b240c017203fbf9414cdec39766e5db9fbeb5b294710915328e999029edd5667fc13db65fb23969391a827eafa405d1f17401bb7b1a9fe72156e967af6a754317b51959b9b6de230a009faf405635f1d758bc04d3205747dfb3bda6ad0966f45a94b550de5eaa87c88ac9fc1e3d93a0e75
alterakey.e = 0x010001
alterakey.d = 0x291876fd091b8f17a68bdaa50f03a6c5e27588352a48f11a9ccf341f639509226178e286000b97dac225ef51f2fd8509ea9dcff10608743bcca7ee75aebf9f5c3f0e89075f59d1c44dbe06e304027e98c8bb9e3d3904d6591234508ce711942458026066dc0b134ac58c777210ac55663884dd4ef01ed0f9113bf0f516482bd9
alterakey.name = "altera"

# Mentor Graphics Corporation
mentor1key = RSAKey()
mentor1key.m = 0xa725f41bf8b2f34cc5f7351011b2fec0f3e2d5e5280c1090af21ff5389fd9e9a2e33d2ab69f04fa75fb405ce8713942942e8372adaa22f109729a948134c3fa627a82b25227e478031c4282f1d8530a13f345ecd10811aa4ac66315b54549cd05c266e1950b7b1633f3def63a3eab43df67e5ed640dafde05cb33309c8e91c19
mentor1key.e = 0x010001
mentor1key.d = 0x23e1d4eeb04c1248f7f2a2d4894828c25958e7dc22e5bc24a3442420d5edb93f960d8ffb3669dd5fabfee4843aa12c5c533db0a2257f4da53d1e3775fe968ecf0ebf5f45de9e59dcb201d18f0916143c7c5cfbfe77ddf8483ceecd9434bfd2adc427a6265572a52e7b5d363f6af6e37f144a660c675fcc2f8a7bb4005b859b51
mentor1key.name = "MGC-VERIF-SIM-RSA-1"

# mentor graphics  MGC-VERIF-SIM-RSA-2
mentor2key = RSAKey()
mentor2key.m = 0xd9f0a71e863d43ba3c3f9a3ee1e219419d40df477cf0d1c6dd52baae046e8d2ce5f95a425f110eb8b97979fa019f94de1991348bc3aff1d4568f938a070318c59a51036a93be6cbe7d9bbfe1023331fd6e11d0e26e36b10633a378c650b43bd8e3207833a2f4a6ff6a92a6f30530113ac00463ddc4989041ba6af647e8d7ad15
mentor2key.e = 0x010001
mentor2key.d = 0x4ed3941e9e3f1a7809c2976f9713c83ecb39e3885fd05a8fab0d7927e7c2749d80b0a7ccc9c5c9a556b07145d3c07c7fb88fa489c8c5a29a4294bbb078c8cdf43fe14f3536f97b91f737ef709eb61411e2578de2bfbc8f2548707b74511469167c285fa8ebf2007a730bfb121e602c10e0ce5f3dc90b88f0e62f1e4d0e70aa21
mentor2key.name = "mentor2"

# List of known private keys
privkeys = (rsa3072, rsa2048, rsa_2013_09, rsa_2014_03, rsa_2015_12, rsa_2016_05, rsa_2017_01, rsa_hybrid1_3k, rsa_2016_09, alterakey, mentor1key, mentor2key)


def rsadec(key, x):
    """RSA decryption"""
    if not CRYPTO_AVAILABLE or key.d == 0:
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

    if struct.unpack_from(">L", key2048, 0)[0] != 0xdfe6242b:
        print(f"HY: key2k= {hexlify(key2048)}", file=sys.stderr)
    if struct.unpack_from(">L", key3072, 0)[0] != 0xe0e2d4d1:
        print(f"HY: key3k= {hexlify(key3072)}", file=sys.stderr)
    if count != 1:
        print(f"HY: count={count}", file=sys.stderr)

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

    key = unwrap(rsa_2013_09, wrapped_key)
    iv = unwrap(rsa_2013_09, wrapped_iv)

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
            
        res = None
        for k in keys:
            thiskey = None
            wrapped = self.decode(k.get("encoding", ""), k.get("key_block", ""))
            
            for privkey in privkeys:
                key = unwrap(privkey, wrapped)
                if key and len(key) == keylen:
                    thiskey = (key, privkey.name, k.get("key_keyname", ""), k.get("key_keyowner", ""))
                    if not self.verbose and thiskey:
                        return thiskey
            
            if self.verbose:
                if thiskey:
                    print(f"--- {k.get('key_keyname', '')} ; {k.get('key_keyowner', '')} ; {hexlify(thiskey[0])} was decrypted using {thiskey[1]}")
                    res = thiskey
                else:
                    print(f"--- {k.get('key_keyname', '')} ; {k.get('key_keyowner', '')} could not be decrypted")
        
        return res

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
                            sys.stdout.buffer.write(plain)
                    else:
                        if len(plain) <= 20:
                            sys.stdout.write(f"** {len(plain)} bytes: {hexlify(plain)}")
                        else:
                            sys.stdout.write(f"** {len(plain)} bytes: {hexlify(plain[:8])} ... {hexlify(plain[-8:])}")
                    sys.stdout.write("\n`pragma end_decoded\n")
        else:
            descriptions = [f"{k.get('key_keyowner', '')}:{k.get('key_keyname', '')}" for k in self.keys]
            if "data_keyname" in self.props:
                descriptions.append(f"DATAKEY/{self.props.get('data_keyowner', '')}:{self.props.get('data_keyname', '')}")
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
