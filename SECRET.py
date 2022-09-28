# Binary Functions
CH_MAJ = lambda bin1, bin2, bin3, bin4, bin5, bin6:(bin3 ^ (bin1 & (bin2 ^ bin3))) ^ (((bin4 | bin5) & bin6) | (bin4 & bin5))
ROTR = lambda bin, n:((bin >> n) | (bin << (8 - n))) % 256

# Internal Hashing Functions
f1 = {q:ROTR(q, 7) ^ ROTR(q, 6) ^ ROTR(q, 2) + (q & 1) for q in range(256)}
f2 = {q:ROTR(q, 5) ^ ROTR(q, 3) ^ ROTR(q, 1) + (q & 1) for q in range(256)}
f3 = {q:ROTR(q, 4) ^ ROTR(q, 3) ^ ROTR(q, 2) + (q & 1) for q in range(256)}

# Helper Functions
to_decimal = lambda bin:[int(bin[q:(q + 8)], 2) for q in range(0, 256, 8)]

def split_blocks(padded):
    for q in range(0, len(padded), 256):
        yield to_decimal(padded[q:(q + 256)])

def pad(plaintext):
    binary = ''.join([bin(q)[2:].zfill(8) for q in plaintext])
    end = bin(len(binary))[2:]

    buffer = '0' * (256 - (len(binary) + len(end)) % 256)
    
    return binary + buffer + end

# Hash Class
class HASH:
    def __init__(self, message = b''):
        self.message = message

        self.S_CONST = [*range(16)]
        self.L_CONST = [*range(32)]

    # Concatenation Function
    def update(self, message):
        self.message = b''.join([self.message, message])

    # Copy Class Function
    def copy(self):
        temp = HASH(self.message)
        return temp

    # Define Waterfall Cipher Function
    def waterfall(self, block):
        return [CH_MAJ(block[0], block[3], block[7], block[29], block[30], block[31]), CH_MAJ(block[1], block[4], block[8], block[30], block[31], block[0]), CH_MAJ(block[2], block[5], block[9], block[31], block[0], block[1]), CH_MAJ(block[3], block[6], block[10], block[0], block[1], block[2]), CH_MAJ(block[4], block[7], block[11], block[1], block[2], block[3]), CH_MAJ(block[5], block[8], block[12], block[2], block[3], block[4]), CH_MAJ(block[6], block[9], block[13], block[3], block[4], block[5]), CH_MAJ(block[7], block[10], block[14], block[4], block[5], block[6]), CH_MAJ(block[8], block[11], block[15], block[5], block[6], block[7]), CH_MAJ(block[9], block[12], block[16], block[6], block[7], block[8]), CH_MAJ(block[10], block[13], block[17], block[7], block[8], block[9]), CH_MAJ(block[11], block[14], block[18], block[8], block[9], block[10]), CH_MAJ(block[12], block[15], block[19], block[9], block[10], block[11]), CH_MAJ(block[13], block[16], block[20], block[10], block[11], block[12]), CH_MAJ(block[14], block[17], block[21], block[11], block[12], block[13]), CH_MAJ(block[15], block[18], block[22], block[12], block[13], block[14]), CH_MAJ(block[16], block[19], block[23], block[13], block[14], block[15]), CH_MAJ(block[17], block[20], block[24], block[14], block[15], block[16]), CH_MAJ(block[18], block[21], block[25], block[15], block[16], block[17]), CH_MAJ(block[19], block[22], block[26], block[16], block[17], block[18]), CH_MAJ(block[20], block[23], block[27], block[17], block[18], block[19]), CH_MAJ(block[21], block[24], block[28], block[18], block[19], block[20]), CH_MAJ(block[22], block[25], block[29], block[19], block[20], block[21]), CH_MAJ(block[23], block[26], block[30], block[20], block[21], block[22]), CH_MAJ(block[24], block[27], block[31], block[21], block[22], block[23]), CH_MAJ(block[25], block[28], block[0], block[22], block[23], block[24]), CH_MAJ(block[26], block[29], block[1], block[23], block[24], block[25]), CH_MAJ(block[27], block[30], block[2], block[24], block[25], block[26]), CH_MAJ(block[28], block[31], block[3], block[25], block[26], block[27]), CH_MAJ(block[29], block[0], block[4], block[26], block[27], block[28]), CH_MAJ(block[30], block[1], block[5], block[27], block[28], block[29]), CH_MAJ(block[31], block[2], block[6], block[28], block[29], block[30])]
    
    # Define Main Cycle Function
    def cycle(self, message_block, hidden_state = [0] * 32):
        for q in range(32):
            temp = message_block[q]

            message_block[q] ^= self.S_CONST[q % 16] ^ self.L_CONST[q % 32] ^ hidden_state[q]

            self.S_CONST[q % 16] = (f1[self.S_CONST[q % 16]] + f2[self.S_CONST[(q - 1) % 16]] + f3[temp]) % 256
            self.L_CONST[q % 32] = (f3[self.L_CONST[q % 32]] + f2[self.L_CONST[(q - 1) % 32]] + f1[temp]) % 256

        return message_block

    # Digest Function
    def digest(self):
        padded = pad(self.message)

        hidden_state = [0] * 32
        for block in split_blocks(padded):
            hidden_state = self.cycle(block, hidden_state)
            hidden_state = self.waterfall(hidden_state)

            self.S_CONST, self.L_CONST = self.L_CONST[16:], self.S_CONST + self.L_CONST[:16]

        output = self.cycle(hidden_state)
        output = self.waterfall(output)

        return bytes([(q + w) % 256 for q, w in zip(output, self.L_CONST)])