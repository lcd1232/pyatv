"""SAPHash + HandGarble + modifiedMD5 — derived from openairplay/airplay2-receiver.

Original source: https://github.com/openairplay/airplay2-receiver/blob/master/ap2/fairplay3.py
Original author: @systemcrash, 2022
Original credit: C OmgHax implementation by Foxsen et al.
Original license: GPLv2

This file is unmodified derived work. See ../__init__.py for license notes.
The print() statements in the original are silenced by redirecting stdout
when called from pyatv. Eventually this should be clean-room reimplemented.
"""
import array


def rol8(_input, count):
    return (((_input << count) & 0xff) | ((_input & 0xff) >> (8 - count))) & 0xff


def rol8x(_input, count) -> int:
    return ((_input << count)) | (_input) >> (8 - count)


def weirdRor8(_input, count) -> int:
    if (count == 0):
        return 0

    return ((_input >> count) & 0xff) | (_input & 0xff) << (8 - count)


def weirdrol8(_input, count) -> int:
    if (count == 0):
        return 0
    return ((_input << count) & 0xff) | (_input & 0xff) >> (8 - count)


def weirdRol32(_input, count) -> int:
    if (count == 0):
        return 0
    return (_input << count) ^ (_input >> (8 - count))


# ==========


class HandGarble():
    def Garble(self, buffer0: [], buffer1: [], buffer2: [], buffer3: [], buffer4: []):
        """
        Sizes at function ingress should be:
        20, 210, 35, 132, 21
        """
        buffer0, buffer1, buffer2, buffer3, buffer4 = bytearray(buffer0), bytearray(buffer1), bytearray(buffer2), bytearray(buffer3), bytearray(buffer4)
        # int tmp, tmp2, tmp3
        # int A, B, C, D, E, M, J, G, F, H, K, R, S, T, U, V, W, X, Y, Z
        """
        // buffer1[64] = A
        // (buffer1[99] / 3) = B
        // 0ABAAABB
        // Then we AND with a complex expression, and add 20 just for good measure
        """
        buffer2[12] = (0x14 + (
            ((buffer1[64] & 92) | (int(buffer1[99] / 3) & 35))
            & buffer4[rol8x((buffer4[buffer1[206] % 21]), 4) % 21])) & 0xff
        print(f'buffer2[12]: {hex(buffer2[12])}')

        # This is a bit simpler: 2*B*B/25
        buffer1[4] = (int(buffer1[99] / 5) * int(buffer1[99] / 5) * 2) & 0xff
        print(f'buffer1[4]: {hex(buffer1[4])}')

        buffer2[34] = 0xb8
        print(f'buffer2[34]: {hex(buffer2[34])}')

        buffer1[153] = (buffer1[153] ^ int(buffer2[buffer1[203] % 35] * buffer2[buffer1[203] % 35] * buffer1[190]) & 0xff) & 0xff
        print(f'buffer1[153]: {hex(buffer1[153])}')

        buffer0[3] = int(buffer0[3] - (((buffer4[buffer1[205] % 21] >> 1) & 80) | 0xe6440)) & 0xff
        print(f'buffer0[3]: {hex(buffer0[3])}')

        buffer0[16] = 0x93
        print(f'buffer0[16]: {hex(buffer0[16])}')

        buffer0[13] = 0x62
        print(f'buffer0[13]: {hex(buffer0[13])}')

        buffer1[33] = (buffer1[33] - (buffer4[buffer1[36] % 21] & 0xf6)) & 0xff
        print(f'buffer1[33]: {hex(buffer1[33])}')

        tmp2 = buffer2[buffer1[67] % 35]
        # This is always 7
        buffer2[12] = 0x07
        print(f'buffer2[12]: {hex(buffer2[12])}')

        # This is pretty easy!
        tmp = buffer0[buffer1[181] % 20]
        b2 = 3136

        buffer1[2] = (buffer1[2] - int(b2)) & 0xff
        print(f'buffer1[2]: {hex(buffer1[2])}')

        buffer0[19] = (buffer4[buffer1[58] % 21]) & 0xff
        print(f'buffer0[19]: {hex(buffer0[19])}')

        buffer3[0] = int(92 - buffer2[buffer1[32] % 35]) & 0xff
        print(f'buffer3[0]: {hex(buffer3[0])}')

        buffer3[4] = buffer2[buffer1[15] % 35] + 0x9e & 0xff
        print(f'buffer3[4]: {hex(buffer3[4])}')

        buffer1[34] = (buffer1[34] + int(buffer4[((buffer2[buffer1[15] % 35] + 0x9e) & 0xff) % 21] / 5) & 0xff) & 0xff
        print(f'buffer1[34]:{hex(buffer1[34])}')

        buffer0[19] = int(buffer0[19] + 0xfffffee6 - ((buffer0[buffer3[4] % 20] >> 1) & 102)) & 0xff
        print(f'buffer0[19]:{hex(buffer0[19])}')

        buffer1[15] = ((3 * (((buffer1[72] >> (buffer4[buffer1[190] % 21] & 7)) ^ (buffer1[72] << ((7 - (buffer4[buffer1[190] % 21] - 1) & 7)))) - (3 * buffer4[buffer1[126] % 21]))) ^ buffer1[15]) & 0xff
        print(f'buffer1[15]:{hex(buffer1[15])}')

        buffer0[15] = (buffer0[15] ^ (buffer2[buffer1[181] % 35] * buffer2[buffer1[181] % 35] * buffer2[buffer1[181] % 35])) & 0xff
        print(f'buffer0[15]:{hex(buffer0[15])}')

        buffer2[4] = buffer2[4] ^ int(buffer1[202] / 3)
        print(f'buffer2[4]: {hex(buffer2[4])}')

        A = (92 - buffer0[buffer3[0] % 20]) & 0xff
        E = (A & 0xc6) | (~buffer1[105] & 0xc6) | (A & ~buffer1[105]) & 0xff
        buffer2[1] = (buffer2[1] + (E * E * E)) & 0xff
        print(f'buffer2[1]: {hex(buffer2[1])}')

        buffer0[19] = (buffer0[19] ^ int(((224 | (buffer4[buffer1[92] % 21] & 27)) * buffer2[buffer1[41] % 35]) / 3)) & 0xff
        print(f'buffer0[19]: {hex(buffer0[19])}')

        buffer1[140] = int(buffer1[140] + weirdRor8(92, buffer1[5] & 7)) & 0xff
        print(f'buffer1[140]: {hex(buffer1[140])}')

        # Is this as simple as it could be?
        buffer2[12] = (buffer2[12] + (((
            (~buffer1[4] ^ buffer2[buffer1[12] % 35])
            | buffer1[182]) & 192) | (~buffer1[4] ^ buffer2[buffer1[12] % 35]) & buffer1[182])) & 0xff
        print(f'buffer2[12]: {hex(buffer2[12])}')

        buffer1[36] = (buffer1[36] + 125) & 0xff
        print(f'buffer1[36]: {hex(buffer1[36])}')

        buffer1[124] = rol8x(((
            ((74 & buffer1[138]) | ((74 | buffer1[138]) & buffer0[15]))
            & buffer0[buffer1[43] % 20]) | (((74 & buffer1[138]) | ((74 | buffer1[138]) & buffer0[15]) | buffer0[buffer1[43] % 20]) & 95)), 4) & 0xff
        print(f'buffer1[124]: {hex(buffer1[124])}')

        buffer3[8] = ((((buffer0[buffer3[4] % 20] & 95) & ((buffer4[buffer1[68] % 21] & 46) << 1)) | 16) ^ 92) & 0xff
        print(f'buffer3[8]: {hex(buffer3[8])}')

        A = buffer1[177] + buffer4[buffer1[79] % 21]
        D = int(((A >> 1) | int((3 * buffer1[148]) / 5)) & buffer2[1]) | ((A >> 1) & int((3 * buffer1[148]) / 5))
        buffer3[12] = (-34 - D) & 0xff
        print(f'buffer3[12]: {hex(buffer3[12])}')

        A = (8 - ((buffer2[22] & 7))) & 0xff
        B = (buffer1[33] >> (A & 7)) & 0xff
        C = (buffer1[33] << (buffer2[22] & 7)) & 0xff

        buffer2[16] = (buffer2[16] + (((buffer2[buffer3[0] % 35] & 159) | buffer0[buffer3[4] % 20] | 8) - ((B ^ C) | 128))) & 0xff
        print(f'buffer2[16]: {hex(buffer2[16])}')

        buffer0[14] = (buffer0[14] ^ (buffer2[buffer3[12] % 35])) & 0xff
        print(f'buffer0[14]: {hex(buffer0[14])}')

        A = weirdrol8(buffer4[buffer0[buffer1[201] % 20] % 21], ((buffer2[buffer1[112] % 35] << 1) & 7)) & 0xff
        D = (buffer0[buffer1[208] % 20] & 131) | (buffer0[buffer1[164] % 20] & 124) & 0xff
        buffer1[19] = (buffer1[19] + ((A & int(D / 5)) | ((A | int(D / 5)) & 37))) & 0xff
        print(f'buffer1[19]: {hex(buffer1[19])}')

        buffer2[8] = (weirdRor8(140, ((buffer4[buffer1[45] % 21] + 92) * (buffer4[buffer1[45] % 21] + 92)) & 7) & 0xff)
        print(f'buffer2[8]: {hex(buffer2[8])}')

        buffer1[190] = 56
        print(f'buffer1[190]: {hex(buffer1[190])}')

        buffer2[8] = (buffer2[8] ^ buffer3[0]) & 0xff
        print(f'buffer2[8]: {hex(buffer2[8])}')

        buffer1[53] = ~int((buffer0[buffer1[83] % 20] | 204) / 5) & 0xff
        print(f'buffer1[53]: {hex(buffer1[53])}')

        buffer0[13] = (buffer0[13] + buffer0[buffer1[41] % 20]) & 0xff
        print(f'buffer0[13]: {hex(buffer0[13])}')

        buffer0[10] = int(int((buffer2[buffer3[0] % 35] & buffer1[2]) | ((buffer2[buffer3[0] % 35] | buffer1[2]) & buffer3[12])) / 15) & 0xff
        print(f'buffer0[10]: {hex(buffer0[10])}')

        A = (((56 | (buffer4[buffer1[2] % 21] & 68)) | buffer2[buffer3[8] % 35]) & 42) | (((buffer4[buffer1[2] % 21] & 68) | 56) & buffer2[buffer3[8] % 35]) & 0xff
        buffer3[16] = ((A * A) + 110) & 0xff
        print(f'buffer3[16]: {hex(buffer3[16])}')

        buffer3[20] = (202 - buffer3[16]) & 0xff
        print(f'buffer3[20]: {hex(buffer3[20])}')

        buffer3[24] = buffer1[151]
        print(f'buffer3[24]: {hex(buffer3[24])}')

        buffer2[13] = (buffer2[13] ^ buffer4[buffer3[0] % 21]) & 0xff
        print(f'buffer2[13]: {hex(buffer2[13])}')

        B = (((buffer2[buffer1[179] % 35] - 38) & 177) | (buffer3[12] & 177)) & 0xff
        C = (((buffer2[buffer1[179] % 35] - 38)) & buffer3[12]) & 0xff
        buffer3[28] = (30 + ((B | C) * (B | C))) & 0xff
        print(f'buffer3[28]: {hex(buffer3[28])}')

        buffer3[32] = (buffer3[28] + 62) & 0xff
        print(f'buffer3[32]: {hex(buffer3[32])}')

        A = (((buffer3[20] + (buffer3[0] & 74)) | ~buffer4[buffer3[0] % 21]) & 121) & 0xff
        B = ((buffer3[20] + (buffer3[0] & 74)) & ~buffer4[buffer3[0] % 21]) & 0xff

        tmp3 = (A | B) & 0xff

        C = (((((A | B) ^ 0xffffffa6) | buffer3[0]) & 4) | (((A | B) ^ 0xffffffa6) & buffer3[0])) & 0xff
        buffer1[47] = ((buffer2[buffer1[89] % 35] + C) ^ buffer1[47]) & 0xff
        print(f'buffer1[47]: {hex(buffer1[47])}')

        buffer3[36] = (((rol8(((tmp & 179) + 68), 2) & buffer0[3]) | (tmp2 & ~buffer0[3])) - 15) & 0xff
        print(f'buffer3[36]: {hex(buffer3[36])}')

        buffer1[123] = (buffer1[123] ^ 221) & 0xff
        print(f'buffer1[123]: {hex(buffer1[123])}')

        A = (int(buffer4[buffer3[0] % 21] / 3) - buffer2[buffer3[4] % 35]) & 0xff
        C = ((((buffer3[0] & 163) + 92) & 246) | (buffer3[0] & 92)) & 0xff
        E = (((C | buffer3[24]) & 54) | (C & buffer3[24])) & 0xff
        buffer3[40] = (A - E) & 0xff
        print(f'buffer3[40]: {hex(buffer3[40])}')

        buffer3[44] = (tmp3 ^ 81 ^ (((buffer3[0] >> 1) & 101) + 26)) & 0xff
        print(f'buffer3[44]: {hex(buffer3[44])}')

        buffer3[48] = (buffer2[buffer3[4] % 35] & 27) & 0xff
        print(f'buffer3[48]: {hex(buffer3[48])}')

        buffer3[52] = 27
        print(f'buffer3[52]: {hex(buffer3[52])}')

        buffer3[56] = 199
        print(f'buffer3[56]: {hex(buffer3[56])}')

        buffer3[64] = (buffer3[4] + ((((
            (((buffer3[40] | buffer3[24]) & 177) | (buffer3[40] & buffer3[24]))
            & ((((buffer4[buffer3[0] % 20] & 177) | 176)) | (buffer4[buffer3[0] % 21] & ~3)))
            | ((((buffer3[40] & buffer3[24]) | ((buffer3[40] | buffer3[24]) & 177)) & 199)
                | (((((buffer4[buffer3[0] % 21] & 1) & 0xff) + 176) | (buffer4[buffer3[0] % 21] & ~3))
                    & buffer3[56]))) & ~buffer3[52]) | buffer3[48])) & 0xff
        print(f'buffer3[64]: {hex(buffer3[64])}')

        buffer2[33] = (buffer2[33] ^ buffer1[26]) & 0xff
        print(f'buffer2[33]: {hex(buffer2[33])}')

        buffer1[106] = (buffer1[106] ^ (buffer3[20] ^ 133)) & 0xff
        print(f'buffer1[106]: {hex(buffer1[106])}')

        buffer2[30] = ((int(buffer3[64] / 3) - (275 | (buffer3[0] & 247))) ^ buffer0[buffer1[122] % 20]) & 0xff
        print(f'buffer2[30]: {hex(buffer2[30])}')

        buffer1[22] = ((buffer2[buffer1[90] % 35] & 95) | 68) & 0xff
        print(f'buffer1[22]: {hex(buffer1[22])}')

        A = ((buffer4[buffer3[36] % 21] & 184) | (buffer2[buffer3[44] % 35] & ~184)) & 0xff
        buffer2[18] = (buffer2[18] + ((A * A * A) >> 1)) & 0xff
        print(f'buffer2[18]: {hex(buffer2[18])}')

        buffer2[5] = (buffer2[5] - buffer4[buffer1[92] % 21]) & 0xff
        print(f'buffer2[5]: {hex(buffer2[5])}')

        A = (((((buffer1[41] & 0xff) & ~24) | (buffer2[buffer1[183] % 35] & 24)) & (buffer3[16] + 53)) | (buffer3[20] & buffer2[buffer3[20] % 35])) & 0xff
        B = ((buffer1[17] & ~buffer3[44]) | (buffer0[buffer1[59] % 20] & buffer3[44])) & 0xff
        buffer2[18] = (buffer2[18] ^ (A * B)) & 0xff
        print(f'buffer2[18]: {hex(buffer2[18])}')

        A = (weirdRor8(buffer1[11], buffer2[buffer1[28] % 35] & 7) & 7) & 0xff
        B = ((((buffer0[buffer1[93] % 20] & ~buffer0[14]) | (buffer0[14] & 150)) & ~28) | (buffer1[7] & 28)) & 0xff
        buffer2[22] = (((((B | weirdrol8(buffer2[buffer3[0] % 35], A)) & buffer2[33]) | (B & weirdrol8(buffer2[buffer3[0] % 35], A))) + 74) & 0xff) & 0xff
        print(f'buffer2[22]: {hex(buffer2[22])}')

        A = buffer4[(buffer0[buffer1[39] % 20] ^ 217) % 21] & 0xff
        buffer0[15] = (buffer0[15] - (
            ((((buffer3[20] | buffer3[0]) & 214) | (buffer3[20] & buffer3[0])) & A)
            | ((((buffer3[20] | buffer3[0]) & 214) | (buffer3[20] & buffer3[0]) | A) & buffer3[32])) & 0xff) & 0xff
        print(f'buffer0[15]: {hex(buffer0[15])}')

        # We need to save T here, and boy is it complicated to calculate!
        B = (((buffer2[buffer1[57] % 35] & buffer0[buffer3[64] % 20]) | ((buffer0[buffer3[64] % 20] | buffer2[buffer1[57] % 35]) & 95) | (buffer3[64] & 45) | 82) & 32) & 0xff
        C = (((buffer2[buffer1[57] % 35] & buffer0[buffer3[64] % 20]) | ((buffer2[buffer1[57] % 35] | buffer0[buffer3[64] % 20]) & 95)) & ((buffer3[64] & 45) | 82)) & 0xff
        D = (((int(buffer3[0] / 3) - (buffer3[64] | buffer1[22]))) ^ (buffer3[28] + 62) ^ ((B | C))) & 0xff
        T = (buffer0[(D & 0xff) % 20] & 0xff) & 0xff

        buffer3[68] = ((
            buffer0[buffer1[99] % 20]
            * buffer0[buffer1[99] % 20]
            * buffer0[buffer1[99] % 20]
            * buffer0[buffer1[99] % 20])
            | buffer2[buffer3[64] % 35]) & 0xff
        print(f'buffer3[68]: {hex(buffer3[68])}')

        U = buffer0[buffer1[50] % 20]  # this is also v100
        W = buffer2[buffer1[138] % 35]
        X = buffer4[buffer1[39] % 21]
        Y = buffer0[buffer1[4] % 20]  # this is also v120
        Z = buffer4[buffer1[202] % 21]  # also v124
        V = buffer0[buffer1[151] % 20]
        S = buffer2[buffer1[14] % 35]
        R = buffer0[buffer1[145] % 20]

        A = ((buffer2[buffer3[68] % 35] & buffer0[buffer1[209] % 20]) | ((buffer2[buffer3[68] % 35] | buffer0[buffer1[209] % 20]) & 24)) & 0xff
        B = weirdrol8(buffer4[buffer1[127] % 21], buffer2[buffer3[68] % 35] & 7) & 0xff
        C = (A & buffer0[10]) | (B & ~buffer0[10]) & 0xff
        D = (7 ^ (buffer4[buffer2[buffer3[36] % 35] % 21] << 1)) & 0xff
        buffer3[72] = ((C & 71) | (D & ~71)) & 0xff
        print(f'buffer3[72]: {hex(buffer3[72])}')

        buffer2[2] = (
            buffer2[2] + ((
                ((buffer0[buffer3[20] % 20] << 1) & 159)
                | (buffer4[buffer1[190] % 21] & ~159))
                & ((
                    ((buffer4[buffer3[64] % 21] & 110)
                        | (buffer0[buffer1[25] % 20] & ~110)) & ~150)
                    | (buffer1[25] & 150)))) & 0xff
        print(f'buffer2[2]: {hex(buffer2[2])}')

        buffer2[14] = (buffer2[14] - (((buffer2[buffer3[20] % 35] & (buffer3[72] ^ buffer2[buffer1[100] % 35])) & ~34) | (buffer1[97] & 34))) & 0xff
        print(f'buffer2[14]: {hex(buffer2[14])}')

        buffer0[17] = 115
        print(f'buffer0[17]: {hex(buffer0[17])}')

        buffer1[23] = (buffer1[23] ^ ((((
            ((buffer4[buffer1[17] % 21] | buffer0[buffer3[20] % 20]) & buffer3[72])
            | (buffer4[buffer1[17] % 21] & buffer0[buffer3[20] % 20])) & int(buffer1[50] / 3))
            | ((((buffer4[buffer1[17] % 21] | buffer0[buffer3[20] % 20]) & buffer3[72])
                | (buffer4[buffer1[17] % 21] & buffer0[buffer3[20] % 20]) | int(buffer1[50] / 3)) & 246)) << 1)) & 0xff
        print(f'buffer1[23]: {hex(buffer1[23])}')

        buffer0[13] = ((((
            ((buffer0[buffer3[40] % 20] | buffer1[10]) & 82)
            | (buffer0[buffer3[40] % 20] & buffer1[10])) & 209)
            | ((buffer0[buffer1[39] % 20] << 1) & 46)) >> 1) & 0xff
        print(f'buffer0[13]: {hex(buffer0[13])}')

        buffer2[33] = buffer2[33] - (buffer1[113] & 9) & 0xff
        print(f'buffer2[33]: {hex(buffer2[33])}')

        buffer2[28] = buffer2[28] - ((((2 | (buffer1[110] & 222)) >> 1) & ~223) | (buffer3[20] & 223)) & 0xff
        print(f'buffer2[28]: {hex(buffer2[28])}')

        J = weirdrol8((V | Z), (U & 7))
        A = (buffer2[16] & T) | (W & ~buffer2[16])
        B = (buffer1[33] & 17) | (X & ~17)
        E = ((Y | int((A + B) / 5)) & 147) | (Y & int((A + B) / 5))
        M = (
            (buffer3[40] & buffer4[((buffer3[8] + J + E) & 0xff) % 21])
            | ((buffer3[40] | buffer4[((buffer3[8] + J + E) & 0xff) % 21]) & buffer2[23]))

        buffer0[15] = ((((buffer4[buffer3[20] % 21] - 48) & ~buffer1[184]) | ((buffer4[buffer3[20] % 21] - 48) & 189) | (189 & ~buffer1[184])) & (M * M * M)) & 0xff
        print(f'buffer0[15]: {hex(buffer0[15])}')

        buffer2[22] = (buffer2[22] + buffer1[183]) & 0xff
        print(f'buffer2[22]: {hex(buffer2[22])}')

        buffer3[76] = ((3 * buffer4[buffer1[1] % 21]) ^ buffer3[0]) & 0xff
        print(f'buffer3[76]: {hex(buffer3[76])}')

        A = buffer2[(buffer3[8] + (J + E) & 0xff) % 35] & 0xff
        F = (((buffer4[buffer1[178] % 21] & A) | ((buffer4[buffer1[178] % 21] | A) & 209)) * buffer0[buffer1[13] % 20]) * (buffer4[buffer1[26] % 21] >> 1)
        G = (F + 0x733ffff9) * 198 - (((F + 0x733ffff9) * 396 + 212) & 212) + 85
        buffer3[80] = (buffer3[36] + (G ^ 148) + ((G ^ 107) << 1) - 127) & 0xff
        print(f'buffer3[80]: {hex(buffer3[80])}')

        buffer3[84] = (((buffer2[buffer3[64] % 35]) & 245) | (buffer2[buffer3[20] % 35] & 10))
        print(f'buffer3[84]: {hex(buffer3[84])}')

        A = buffer0[buffer3[68] % 20] | 81
        buffer2[18] = ((buffer2[18] - (((A * A * A) & ~buffer0[15]) | (int(buffer3[80] / 15) & buffer0[15])))) & 0xff
        print(f'buffer2[18]: {hex(buffer2[18])}')

        buffer3[88] = (
            buffer3[8] + J + E - buffer0[buffer1[160] % 20]
            + int(buffer4[buffer0[((buffer3[8] + J + E) & 255) % 20] % 21] / 3)) & 0xff
        print(f'buffer3[88]: {hex(buffer3[88])}')

        B = ((R ^ buffer3[72]) & ~198) | ((S * S) & 198)
        F = ((buffer4[buffer1[69] % 21] & buffer1[172])
             | ((buffer4[buffer1[69] % 21] | buffer1[172]) & ((buffer3[12] - B) + 77)))
        buffer0[16] = (147 - ((buffer3[72] & ((F & 251) | 1)) | (((F & 250) | buffer3[72]) & 198))) & 0xff
        print(f'buffer0[16]: {hex(buffer0[16])}')

        C = (buffer4[buffer1[168] % 21] & buffer0[buffer1[29] % 20] & 7) | ((buffer4[buffer1[168] % 21] | buffer0[buffer1[29] % 20]) & 6)
        F = (buffer4[buffer1[155] % 21] & buffer1[105]) | ((buffer4[buffer1[155] % 21] | buffer1[105]) & 141)
        buffer0[3] = (buffer0[3] - buffer4[weirdRol32(F, C) % 21]) & 0xff
        print(f'buffer0[3]: {hex(buffer0[3])}')

        buffer1[5] = (weirdRor8(buffer0[12], (int(buffer0[buffer1[61] % 20] / 5) & 7)) ^ int(((~buffer2[buffer3[84] % 35]) & 0xffffffff) / 5)) & 0xff
        print(f'buffer1[5]: {hex(buffer1[5])}')

        buffer1[198] = (buffer1[198] + buffer1[3]) & 0xff
        print(f'buffer1[198]: {hex(buffer1[198])}')

        A = (162 | buffer2[buffer3[64] % 35])
        buffer1[164] = (buffer1[164] + int((A * A) / 5)) & 0xff
        print(f'buffer1[164]: {hex(buffer1[164])}')

        G = weirdRor8(139, (buffer3[80] & 7))
        C = ((buffer4[buffer3[64] % 21] * buffer4[buffer3[64] % 21] * buffer4[buffer3[64] % 21]) & 95) | (buffer0[buffer3[40] % 20] & ~95)
        buffer3[92] = ((G & 12) | (buffer0[buffer3[20] % 20] & 12) | (G & buffer0[buffer3[20] % 20]) | C) & 0xff
        print(f'buffer3[92]: {hex(buffer3[92])}')

        buffer2[12] = (buffer2[12] + int(((buffer1[103] & 32) | (buffer3[92] & ((buffer1[103] | 60))) | 16) / 3) & 0xff) & 0xff
        print(f'buffer2[12]: {hex(buffer2[12])}')

        buffer3[96] = buffer1[143]
        print(f'buffer3[96]: {hex(buffer3[96])}')

        buffer3[100] = 27
        print(f'buffer3[100]: {hex(buffer3[100])}')

        buffer3[104] = ((((buffer3[40] & ~buffer2[8]) | (buffer1[35] & buffer2[8])) & buffer3[64]) ^ 119) & 0xff
        print(f'buffer3[104]: {hex(buffer3[104])}')

        buffer3[108] = (238 & ((((buffer3[40] & ~buffer2[8]) | (buffer1[35] & buffer2[8])) & buffer3[64]) << 1)) & 0xff
        print(f'buffer3[108]: {hex(buffer3[108])}')

        buffer3[112] = ((~buffer3[64] & int(buffer3[84] / 3)) ^ 49) & 0xff
        print(f'buffer3[112]: {hex(buffer3[112])}')

        buffer3[116] = (98 & ((~buffer3[64] & int(buffer3[84] / 3)) << 1)) & 0xff
        print(f'buffer3[116]: {hex(buffer3[116])}')

        A = (buffer1[35] & buffer2[8]) | (buffer3[40] & ~buffer2[8])

        # finale
        B = (A & buffer3[64]) | ((int(buffer3[84] / 3) & ~buffer3[64]))
        buffer1[143] = (buffer3[96] - (
            (B & (86 + ((buffer1[172] & 64) >> 1)))
            | (((((buffer1[172] & 65) >> 1) ^ 86) | ((~buffer3[64] & int(buffer3[84] / 3))
                | (((buffer3[40] & ~buffer2[8]) | (buffer1[35] & buffer2[8])) & buffer3[64]))) & buffer3[100]))) & 0xff
        print(f'buffer1[143]: {hex(buffer1[143])}')

        buffer2[29] = 162
        print()

        A = (((buffer4[buffer3[88] % 21] & 160) | (buffer0[buffer1[125] % 20] & 95)) >> 1) & 0xff
        B = buffer2[(buffer1[149] & 0xff) % 35] ^ (buffer1[43] * buffer1[43]) & 0xff
        buffer0[15] = (buffer0[15] + ((B & A) | ((A | B) & 115))) & 0xff
        print(f'buffer0[15]: {hex(buffer0[15])}')

        buffer3[120] = (buffer3[64] - buffer0[buffer3[40] % 20]) & 0xff
        print(f'buffer3[120]: {hex(buffer3[120])}')

        buffer1[95] = buffer4[buffer3[20] % 21]
        print(f'buffer1[95]: {hex(buffer1[95])}')

        A = weirdRor8(buffer2[buffer3[80] % 35], (
            buffer2[buffer1[17] % 35]
            * buffer2[buffer1[17] % 35]
            * buffer2[buffer1[17] % 35]) & 7)

        buffer0[7] = (buffer0[7] - ((A * A))) & 0xff
        print(f'buffer0[7]: {hex(buffer0[7])}')

        buffer2[8] = (buffer2[8] - buffer1[184] + (buffer4[buffer1[202] % 21] * buffer4[buffer1[202] % 21] * buffer4[buffer1[202] % 21])) & 0xff
        print(f'buffer2[8]: {hex(buffer2[8])}')

        buffer0[16] = ((buffer2[buffer1[102] % 35] << 1) & 132) & 0xff
        print(f'buffer0[16]: {hex(buffer0[16])}')

        buffer3[124] = ((buffer4[buffer3[40] % 21] >> 1) ^ buffer3[68]) & 0xff
        print(f'buffer3[124]: {hex(buffer3[124])}')

        buffer0[7] = (buffer0[7] - (buffer0[buffer1[191] % 20] - (((buffer4[buffer1[80] % 21] << 1) & ~177) | (buffer4[buffer4[buffer3[88] % 21] % 21] & 177)))) & 0xff
        print(f'buffer0[7]: {hex(buffer0[7])}')

        buffer0[6] = buffer0[buffer1[119] % 20]
        print(f'buffer0[6]: {hex(buffer0[6])}')

        A = ((buffer4[buffer1[190] % 21] & ~209) | (buffer1[118] & 209))
        B = (buffer0[buffer3[120] % 20] * buffer0[buffer3[120] % 20])
        buffer0[12] = ((buffer0[buffer3[84] % 20] ^ (buffer2[buffer1[71] % 35] + buffer2[buffer1[15] % 35])) & ((A & B) | ((A | B) & 27))) & 0xff
        print(f'buffer0[12]: {hex(buffer0[12])}')

        B = ((buffer1[32] & buffer2[buffer3[88] % 35]) | ((buffer1[32] | buffer2[buffer3[88] % 35]) & 23))
        D = (((buffer4[buffer1[57] % 21] * 231) & 169) | (B & 86))
        F = ((((buffer0[buffer1[82] % 20] & ~29) | (buffer4[buffer3[124] % 21] & 29)) & 190) | (buffer4[int(D / 5) % 21] & ~190))
        H = (buffer0[buffer3[40] % 20] * buffer0[buffer3[40] % 20] * buffer0[buffer3[40] % 20])
        K = ((H & buffer1[82]) | (H & 92) | (buffer1[82] & 92))

        buffer3[128] = (((F & K) | ((F | K) & 192)) ^ int(D / 5)) & 0xff
        print(f'buffer3[128]: {hex(buffer3[128])}')

        buffer2[25] = (buffer2[25] ^ (((buffer0[buffer3[120] % 20] << 1) * buffer1[5]) - (weirdrol8(buffer3[76], (buffer4[buffer3[124] % 21] & 7)) & (buffer3[20] + 110)))) & 0xff
        print(f'buffer2[25]: {hex(buffer2[25])}')

        return buffer0, buffer1, buffer2, buffer3, buffer4



class modifiedMD5():
    def __init__(self):
        self._shift = [
            7, 12, 17, 22, 7, 12, 17, 22,
            7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23,
            4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21,
            6, 10, 15, 21, 6, 10, 15, 21]

    def modifiedMD5(self, originalblockIn: bytes, keyIn: bytes) -> bytes:
        """
        Return keyOut (16 bytes)
        consumes:
        64 bytes originalblockIn
        16 bytes keyIn
        """
        blockIn = originalblockIn[0:64]
        block_words = array.array('I', blockIn)
        key_words = array.array('I', keyIn)
        keyOut = bytearray(16)
        out_words = array.array('I', memoryview(keyOut))
        # systemcrash: mask with 32bits so we don't get overflow.
        A = key_words[0] & 0xffffffff
        B = key_words[1] & 0xffffffff
        C = key_words[2] & 0xffffffff
        D = key_words[3] & 0xffffffff
        for i in range(0, 64):
            _input = 0
            j = 0
            if (i < 16):
                j = i
            elif(i < 32):
                j = (5 * i + 1) % 16
            elif (i < 48):
                j = (3 * i + 5) % 16
            elif (i < 64):
                j = 7 * i % 16
            # print(f'j: {j}')
            _input = (blockIn[4 * j] << 24 | blockIn[(4 * j) + 1] << 16 | blockIn[(4 * j) + 2] << 8 | blockIn[(4 * j) + 3]) & 0xffffffff
            # print(hex(blockIn[4 * j] << 24))
            # print(hex(blockIn[(4 * j) + 1] << 16))
            # print(hex(blockIn[(4 * j) + 2] << 8))
            # print(hex(blockIn[(4 * j) + 3]))
            # print(f'input: {hex(_input)}')
            print(f"Key = {hex(A & 0xffffffff) }")
            A = A & 0xffffffff
            Z = A + _input + int((1 << 32) * abs(math.sin(i + 1)))
            Z = Z & 0xffffffff
            if (i < 16):
                Z = self.Rol(Z + self.F(B, C, D), self._shift[i])
            elif (i < 32):
                Z = self.Rol(Z + self.G(B, C, D), self._shift[i])
            elif (i < 48):
                Z = self.Rol(Z + self.H(B, C, D), self._shift[i]) & 0xffffffff
            elif (i < 64):  # I->J: letter I is ambiguous in some fonts.
                Z = self.Rol(Z + self.J(B, C, D), self._shift[i])
            if(i == 63):
                print("Ror is %08x" % Z)

            print("Output of round %d: %08X + %08X = %08X (shift %d, constant %08X)" % (i, Z & 0xffffffff, B & 0xffffffff, Z + B & 0xffffffff, self._shift[i], int((1 << 32) * abs(math.sin(i + 1)))))
            Z = Z + B
            tmp = D
            D = C
            C = B
            B = Z
            A = tmp
            if (i == 31):
                # swapsies
                print("%08x <-> %08x" % (block_words[A & 15], block_words[B & 15]))
                block_words[A & 15], block_words[B & 15] = block_words[B & 15], block_words[A & 15]
                print("%08x <-> %08x" % (block_words[C & 15], block_words[D & 15]))
                block_words[C & 15], block_words[D & 15] = block_words[D & 15], block_words[C & 15]
                print("%08x <-> %08x" % (block_words[(A & (15 << 4)) >> 4], block_words[(B & (15 << 4)) >> 4]))
                block_words[(A & (15 << 4)) >> 4], block_words[(B & (15 << 4)) >> 4] = block_words[(B & (15 << 4)) >> 4], block_words[(A & (15 << 4)) >> 4]
                print("%08x <-> %08x" % (block_words[(A & (15 << 8)) >> 8], block_words[(B & (15 << 8)) >> 8]))
                block_words[(A & (15 << 8)) >> 8], block_words[(B & (15 << 8)) >> 8] = block_words[(B & (15 << 8)) >> 8], block_words[(A & (15 << 8)) >> 8]
                print("%08x <-> %08x" % (block_words[(A & (15 << 12)) >> 12], block_words[(B & (15 << 12)) >> 12]))
                block_words[(A & (15 << 12)) >> 12], block_words[(B & (15 << 12)) >> 12] = block_words[(B & (15 << 12)) >> 12], block_words[(A & (15 << 12)) >> 12]
                blockIn = bytearray(array.array('I', block_words.tobytes()))

        print(f"%08X %08X %08X %08X" % (A, B, C, D))
        print("Out:")
        print("%08x + %08x = %08x" % (key_words[0], A & 0xffffffff, key_words[0] + A & 0xffffffff))
        print("%08x + %08x = %08x" % (key_words[1], B & 0xffffffff, key_words[1] + B & 0xffffffff))
        print("%08x + %08x = %08x" % (key_words[2], C & 0xffffffff, key_words[2] + C & 0xffffffff))
        print("%08x + %08x = %08x" % (key_words[3], D & 0xffffffff, key_words[3] + D & 0xffffffff))
        out_words[0] = key_words[0] + A & 0xffffffff
        out_words[1] = key_words[1] + B & 0xffffffff
        out_words[2] = key_words[2] + C & 0xffffffff
        out_words[3] = key_words[3] + D & 0xffffffff
        return out_words.tobytes()  # keyOut

    def F(self, B: int, C: int, D: int):
        return (B & C) | (~B & D)

    def G(self, B: int, C: int, D: int):
        return (B & D) | (C & ~D)

    def H(self, B: int, C: int, D: int):
        return B ^ C ^ D

    def J(self, B: int, C: int, D: int):
        return C ^ (B | ~D)

    def Rol(self, _input: int, count: int):
        return ((_input << count) & 0xffffffff) | (_input & 0xffffffff) >> (32 - count)

# =============


class SAPHash():
    def __init__(self):
        self._handGarble = HandGarble()

    def hash(self, blockIn: bytes) -> bytes:
        """
        Expects a block of bytes, 210 bytes long.
        """
        # make dword array from blockIn
        block_words = array.array('I', blockIn)
        # 20 bytes
        buffer0 = [0x96, 0x5F, 0xC6, 0x53, 0xF8, 0x46, 0xCC, 0x18, 0xDF, 0xBE, 0xB2, 0xF8, 0x38, 0xD7, 0xEC, 0x22, 0x03, 0xD1, 0x20, 0x8F]
        buffer1 = bytearray(210)  # 210 bytes
        # 35 bytes
        buffer2 = [0x43, 0x54, 0x62, 0x7A, 0x18, 0xC3, 0xD6, 0xB3, 0x9A, 0x56, 0xF6, 0x1C, 0x14, 0x3F, 0x0C, 0x1D, 0x3B, 0x36, 0x83, 0xB1, 0x39, 0x51, 0x4A, 0xAA, 0x09, 0x3E, 0xFE, 0x44, 0xAF, 0xDE, 0xC3, 0x20, 0x9D, 0x42, 0x3A]
        buffer3 = bytearray(132)  # 132 bytes
        # 21 bytes
        buffer4 = [0xED, 0x25, 0xD1, 0xBB, 0xBC, 0x27, 0x9F, 0x02, 0xA2, 0xA9, 0x11, 0x00, 0x0C, 0xB3, 0x52, 0xC0, 0xBD, 0xE3, 0x1B, 0x49, 0xC7]
        # 11 ints
        i0_index = [18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30]

        # w, x, y, z  # used locally
        i, j = 0, 0

        # Load the input into the buffer
        for i in range(0, 210, 1):
            # We need to swap the byte order around so it is the right endianness
            in_word = block_words[((i % 64) >> 2)]
            in_byte = (in_word >> ((3 - (i % 4)) << 3)) & 0xff
            buffer1[i] = in_byte
        # print('about to saphash')
        print(f'saphash: buffer1[i] (load): {buffer1.hex(" ")}')

        print('saphash: buffer1 (scramble): ')
        # Next a scrambling
        for i in range(0, 840, 1):
            # We have to do unsigned, 32-bit modulo, or we get the wrong indices
            # print(f'xi:{abs(((i - 155) & 0xffffffff) % 210)} ', end='', flush=False)
            x = buffer1[abs(((i - 155) & 0xffffffff) % 210)]
            # print(f"x:{hex(x)} ", end='', flush=False)
            # print(f'yi:{abs(((i - 57) & 0xffffffff) % 210)} ', end='', flush=False)
            y = buffer1[abs(((i - 57) & 0xffffffff) % 210)]
            # print(f"y:{hex(y)} ", end='', flush=False)
            # print(f'zi:{abs(((i - 13) & 0xffffffff) % 210)} ', end='', flush=False)
            z = buffer1[abs(((i - 13) & 0xffffffff) % 210)]
            # print(f"z:{hex(z)} ", end='', flush=False)
            # print(f"wi:{abs((i & 0xffffffff) % 210)} ", end='', flush=False)
            w = buffer1[abs((i & 0xffffffff) % 210)]
            # print(f"w:{hex(w)} ", end='', flush=False)
            # print(f"r8:{hex((rol8(y, 5) + (rol8(z, 3) ^ w) - rol8(x, 7)) & 0xff)} ", end='', flush=False)
            buffer1[i % 210] = (rol8(y, 5) + (rol8(z, 3) ^ w) - rol8(x, 7)) & 0xff
            print(f'{hex(buffer1[i%210])} ', end='', flush=False)
        print('\n', flush=True)

        print("Garbling...")
        # I have no idea what this is doing (yet), but it gives the right output
        buffer0, buffer1, buffer2, buffer3, buffer4 = self._handGarble.Garble(buffer0, buffer1, buffer2, buffer3, buffer4)

        # Fill the output with 0xE1
        keyOut = bytearray(b'\xE1' * 16)

        # Now we use all the buffers we have calculated to grind out the output. First buffer3
        for i in range(0, 11, 1):
            # Note that this is addition (mod 255) and not XOR
            # Also note that we only use certain indices
            # And that index 3 is hard-coded to be 0x3d (Maybe we can hack this up by changing buffer3[0] to be 0xdc?
            if (i == 3):
                keyOut[i] = 0x3d
            else:
                keyOut[i] = ((keyOut[i] + buffer3[i0_index[i] * 4]) & 0xff)

        # Then buffer0
        for i in range(0, 20, 1):
            keyOut[i % 16] = (keyOut[i % 16] ^ buffer0[i]) & 0xff

        # Then buffer2
        for i in range(0, 35, 1):
            keyOut[i % 16] = (keyOut[i % 16] ^ buffer2[i]) & 0xff

        # Do buffer1
        for i in range(0, 210, 1):
            keyOut[(i % 16)] = (keyOut[(i % 16)] ^ buffer1[i]) & 0xff

        # Now we do a kind of reverse-scramble
        for j in range(0, 16, 1):
            for i in range(0, 16, 1):
                x = keyOut[(((i - 7) & 0xffffffff) % 16)]
                y = keyOut[i % 16]
                z = keyOut[(((i - 37) & 0xffffffff) % 16)]
                w = keyOut[(((i - 177) & 0xffffffff) % 16)]
                keyOut[i] = (rol8(x, 1) ^ y ^ rol8(z, 6) ^ rol8(w, 5))

        return keyOut
