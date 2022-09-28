def HMAC(key, msg = None, digestmod = ''):
    if len(key) > 64:
        key = digestmod(key).digest()

    key = key.ljust(64, b'\0')

    inner = digestmod(bytes(x ^ 0x36 for x in key))
    outer = digestmod(bytes(x ^ 0x5C for x in key))

    inner.update(msg)

    h = outer.copy()
    h.update(inner.digest())
    return h.digest()