# Substitution Constants and Inverses
s_box = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

inv_s_box = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

# Expansion Constants
r_con = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
]

# Internal Functions
substitute = lambda state:[[s_box[state[0][0]], s_box[state[0][1]], s_box[state[0][2]], s_box[state[0][3]]], [s_box[state[1][0]], s_box[state[1][1]], s_box[state[1][2]], s_box[state[1][3]]], [s_box[state[2][0]], s_box[state[2][1]], s_box[state[2][2]], s_box[state[2][3]]], [s_box[state[3][0]], s_box[state[3][1]], s_box[state[3][2]], s_box[state[3][3]]]]
substitute_i = lambda state:[[inv_s_box[state[0][0]], inv_s_box[state[0][1]], inv_s_box[state[0][2]], inv_s_box[state[0][3]]], [inv_s_box[state[1][0]], inv_s_box[state[1][1]], inv_s_box[state[1][2]], inv_s_box[state[1][3]]], [inv_s_box[state[2][0]], inv_s_box[state[2][1]], inv_s_box[state[2][2]], inv_s_box[state[2][3]]], [inv_s_box[state[3][0]], inv_s_box[state[3][1]], inv_s_box[state[3][2]], inv_s_box[state[3][3]]]]

row_shift = lambda state:[[state[0][0], state[1][1], state[2][2], state[3][3]], [state[1][0], state[2][1], state[3][2], state[0][3]], [state[2][0], state[3][1], state[0][2], state[1][3]], [state[3][0], state[0][1], state[1][2], state[2][3]]]
row_shift_i = lambda state:[[state[0][0], state[3][1], state[2][2], state[1][3]], [state[1][0], state[0][1], state[3][2], state[2][3]], [state[2][0], state[1][1], state[0][2], state[3][3]], [state[3][0], state[2][1], state[1][2], state[0][3]]]

xor = lambda x, y:[x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]]
xor2 = lambda x, y:[x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3], x[4] ^ y[4], x[5] ^ y[5], x[6] ^ y[6], x[7] ^ y[7], x[8] ^ y[8], x[9] ^ y[9], x[10] ^ y[10], x[11] ^ y[11], x[12] ^ y[12], x[13] ^ y[13], x[14] ^ y[14], x[15] ^ y[15]]

xor_2d = lambda x, y:[xor(a, b) for a, b in zip(x, y)]

f = lambda a: ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1

mix_columns = lambda state:[[state[0][1] ^ state[0][2] ^ state[0][3] ^ f(state[0][0] ^ state[0][1]), state[0][2] ^ state[0][3] ^ state[0][0] ^ f(state[0][1] ^ state[0][2]), state[0][3] ^ state[0][0] ^ state[0][1] ^ f(state[0][2] ^ state[0][3]), state[0][0] ^ state[0][1] ^ state[0][2] ^ f(state[0][3] ^ state[0][0])], [state[1][1] ^ state[1][2] ^ state[1][3] ^ f(state[1][0] ^ state[1][1]), state[1][2] ^ state[1][3] ^ state[1][0] ^ f(state[1][1] ^ state[1][2]), state[1][3] ^ state[1][0] ^ state[1][1] ^ f(state[1][2] ^ state[1][3]), state[1][0] ^ state[1][1] ^ state[1][2] ^ f(state[1][3] ^ state[1][0])], [state[2][1] ^ state[2][2] ^ state[2][3] ^ f(state[2][0] ^ state[2][1]), state[2][2] ^ state[2][3] ^ state[2][0] ^ f(state[2][1] ^ state[2][2]), state[2][3] ^ state[2][0] ^ state[2][1] ^ f(state[2][2] ^ state[2][3]), state[2][0] ^ state[2][1] ^ state[2][2] ^ f(state[2][3] ^ state[2][0])], [state[3][1] ^ state[3][2] ^ state[3][3] ^ f(state[3][0] ^ state[3][1]), state[3][2] ^ state[3][3] ^ state[3][0] ^ f(state[3][1] ^ state[3][2]), state[3][3] ^ state[3][0] ^ state[3][1] ^ f(state[3][2] ^ state[3][3]), state[3][0] ^ state[3][1] ^ state[3][2] ^ f(state[3][3] ^ state[3][0])]]
mix_columns_i = lambda state:mix_columns([[state[0][0] ^ f(f(state[0][0] ^ state[0][2])), state[0][1] ^ f(f(state[0][1] ^ state[0][3])), state[0][2] ^ f(f(state[0][0] ^ state[0][2])), state[0][3] ^ f(f(state[0][1] ^ state[0][3]))], [state[1][0] ^ f(f(state[1][0] ^ state[1][2])), state[1][1] ^ f(f(state[1][1] ^ state[1][3])), state[1][2] ^ f(f(state[1][0] ^ state[1][2])), state[1][3] ^ f(f(state[1][1] ^ state[1][3]))], [state[2][0] ^ f(f(state[2][0] ^ state[2][2])), state[2][1] ^ f(f(state[2][1] ^ state[2][3])), state[2][2] ^ f(f(state[2][0] ^ state[2][2])), state[2][3] ^ f(f(state[2][1] ^ state[2][3]))], [state[3][0] ^ f(f(state[3][0] ^ state[3][2])), state[3][1] ^ f(f(state[3][1] ^ state[3][3])), state[3][2] ^ f(f(state[3][0] ^ state[3][2])), state[3][3] ^ f(f(state[3][1] ^ state[3][3]))]])

# Helper Functions
bytes2matrix = lambda text:[[*text[q:(q + 4)]] for q in range(0, len(text), 4)]
matrix2bytes = lambda matrix:bytes(matrix[0] + matrix[1] + matrix[2] + matrix[3])

def split_blocks(message):
    for q in range(0, len(message), 16):
        yield message[q:(q + 16)]

# Pad & Unpad Functions
def pad(plaintext):
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    padding_len = plaintext[-1]
    message, _ = plaintext[:-padding_len], plaintext[-padding_len:]
    return message

# Advanced Encryption Standard Function
class AES:
    def __init__(self, master_key):
        self.rounds = 14

        self.key_matrices = self.expand(master_key)

    # Expand Key Needed Size
    def expand(self, master_key):
        key_cols = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_cols) < (self.rounds + 1) * 4:
            word = [*key_cols[-1]]

            if not len(key_cols) % iteration_size:
                word += [word.pop(0)]
                word = [s_box[b] for b in word]
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_cols) % iteration_size == 4:
                word = [s_box[b] for b in word]

            word = bytes(xor(word, key_cols[-iteration_size]))
            key_cols += [word]

        return [key_cols[(q * 4):((q + 1) * 4)] for q in range(len(key_cols) // 4)]

    # Encrypt Block of Plain Text 
    def encrypt_block(self, plaintext):
        plain_state = bytes2matrix(plaintext)

        plain_state = xor_2d(plain_state, self.key_matrices[0])

        for q in range(1, self.rounds):
            plain_state = substitute(plain_state)
            plain_state = row_shift(plain_state)
            plain_state = mix_columns(plain_state)
            plain_state = xor_2d(plain_state, self.key_matrices[q])

        plain_state = substitute(plain_state)
        plain_state = row_shift(plain_state)
        plain_state = xor_2d(plain_state, self.key_matrices[-1])

        return matrix2bytes(plain_state)

    # Decrypt Block of Cipher Text
    def decrypt_block(self, ciphertext):
        cipher_state = bytes2matrix(ciphertext)

        cipher_state = xor_2d(cipher_state, self.key_matrices[-1])
        cipher_state = row_shift_i(cipher_state)
        cipher_state = substitute_i(cipher_state)

        for q in range(self.rounds - 1, 0, -1):
            cipher_state = xor_2d(cipher_state, self.key_matrices[q])
            cipher_state = mix_columns_i(cipher_state)
            cipher_state = row_shift_i(cipher_state)
            cipher_state = substitute_i(cipher_state)

        cipher_state = xor_2d(cipher_state, self.key_matrices[0])

        return matrix2bytes(cipher_state)

    # Encrypt via Cipher Block Chaining
    def encrypt_cbc(self, plaintext, init_vec):
        plaintext = pad(plaintext)

        blocks = []
        prev = init_vec
        for plaintext_block in split_blocks(plaintext):
            blocks += [self.encrypt_block(bytes(xor2(plaintext_block, prev)))]
            prev = blocks[-1]

        return b''.join(blocks)

    # Decrypt via Cipher Block Chaining
    def decrypt_cbc(self, ciphertext, init_vec):
        blocks = []
        prev = init_vec
        for ciphertext_block in split_blocks(ciphertext):
            blocks.append(bytes(xor2(prev, self.decrypt_block(ciphertext_block))))
            prev = ciphertext_block

        return unpad(b''.join(blocks))