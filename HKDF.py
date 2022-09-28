def HKDF(input_key_material, prf, salt = b'', info = b'', length = 32):
    salt = salt or bytes([0] * 32)
    prk = prf(salt, input_key_material)

    temp = b''
    output = b''
    for q in range(-(length // -32)):
        temp = prf(prk, temp + info + bytes([q + 1]))
        output += temp

    return output[:length]