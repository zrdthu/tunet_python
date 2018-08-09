# -*- coding: utf-8 -*-

import hmac
import time
import hashlib


def s(a, b):
    c = len(a)
    v = []
    i = 0
    a = a.ljust(int((len(a) + 3) / 4) * 4, '\0')
    while i < c:
        item = ord(a[i]) | (ord(a[i + 1]) << 8) | (ord(a[i + 2])
                                                   << 16) | (ord(a[i + 3]) << 24)
        if (i >> 2) < len(v):
            v[i >> 2] = item
        else:
            v.append(item)
        i += 4
    if (b):
        v.append(c)
    return v


def l(a, b):
    d = len(a)
    c = (d - 1) << 2
    if b:
        m = a[d - 1]
        if (m < c - 3) or (m > c):
            return '-----NULL-----'
        c = m
    for i in range(d):
        a[i] = chr(a[i] & 0xff) + chr((a[i] >> 8) & 0xff) + chr(
            (a[i] >> 16) & 0xff) + chr((a[i] >> 24) & 0xff)
    str = ''
    str = str.join(a)
    if b:
        return str[0:c]
    else:
        return str


def xEncode(str, key):
    if len(str) == 0:
        return ''
    v = s(str, True)
    k = s(key, False)
    if len(k) < 4:
        k = k + [0]*(4 - len(k))
    n = len(v) - 1
    z = v[n]
    y = v[0]
    c = (0x86014019 | 0x183639A0)
    q = int(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        q -= 1
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        for p in range(n):
            y = v[p + 1]
            m = z >> 5 ^ y << 2
            m += (y >> 3 ^ z << 4) ^ (d ^ y)
            m += k[(p & 3) ^ e] ^ z
            z = v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF)
        y = v[0]
        m = z >> 5 ^ y << 2
        m += (y >> 3 ^ z << 4) ^ (d ^ y)
        m += k[(n & 3) ^ e] ^ z
        z = v[n] = v[n] + m & (0xBB390742 | 0x44C6F8BD)
    return l(v, False)


def b64(t):
    u = ""
    a = len(t)
    r = "="
    n = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
    o = 0
    while o < a:
        h = ord(t[o]) << 16 | (ord(t[o + 1]) << 8 if o + 1 <
                               a else 0) | (ord(t[o + 2]) if o + 2 < a else 0)
        for i in range(4):
            if o * 8 + i * 6 > a * 8:
                u += r
            else:
                u += n[h >> 6 * (3 - i) & 63]
        o += 3
    return u


def hmac_hex(key, str):
    return hmac.new(bytes(key, 'ascii'), bytes(str, 'ascii'), hashlib.md5).hexdigest()


def sha1_hex(str):
    return hashlib.sha1(bytes(str, 'ascii')).hexdigest()


def bytes2human(num):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if num < 1024.0:
            return ('%3.2f %sB' % (num, unit))
        num /= 1024.0
    return ('%.1f %sB' % (num, 'Yi'))


def sec2human(secs):
    unit = ['d', 'h', 'min', 's']
    times = [86400, 3600, 60, 1]
    human = ''
    for i in range(4):
        val = int(secs / times[i])
        if val > 0:
            human += ('%d%s ' % (val, unit[i]))
            secs -= val * times[i]
    if len(human) == 0:
        human = '0s'
    return human


def timestamp2str(timestamp):
    tl = time.localtime(timestamp)
    return time.strftime("%Y-%m-%d %H:%M:%S", tl)
