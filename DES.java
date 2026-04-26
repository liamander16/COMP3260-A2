/// DES.java
///
/// Contains all DES lookup tables, helper utilities, and the four F-function
/// variants (f0–f3) used for avalanche analysis. Also exposes encrypt() and
/// decrypt() which are called by Encryption.java and Decryption.java.

class DES {

    // =========================================================================
    // Permutation / selection tables  (all values are 1-indexed per DES spec)
    // =========================================================================

    /// Initial Permutation (IP) — rearranges the 64-bit plaintext block
    /// before the first Feistel round.
    private static final int[] IP = {
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
        64, 56, 48, 40, 32, 24, 16,  8,
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7
    };

    /// Final Permutation (FP / IP⁻¹) — inverse of IP, applied after the 16th
    /// Feistel round to produce the ciphertext.
    private static final int[] FP = {
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    };

    /// Expansion Permutation (E) — expands the 32-bit right half to 48 bits
    /// by duplicating the border bits of each 4-bit group.
    private static final int[] E = {
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    };

    /// Inverse Expansion Permutation (E⁻¹) — compresses 48 bits back to 32
    /// by selecting only the four middle (non-duplicated) bits from each of
    /// the eight 6-bit groups produced by E. Used by DES2 in place of S-boxes.
    private static final int[] E_INV = {
         2,  3,  4,  5,
         8,  9, 10, 11,
        14, 15, 16, 17,
        20, 21, 22, 23,
        26, 27, 28, 29,
        32, 33, 34, 35,
        38, 39, 40, 41,
        44, 45, 46, 47
    };

    /// Permutation P — permutes the 32-bit output of the S-boxes within the
    /// F-function. Provides diffusion across the block.
    private static final int[] P = {
        16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
    };

    /// Permuted Choice 1 (PC1) — selects 56 bits from the 64-bit key,
    /// discarding the 8 parity bits (every 8th bit: positions 8,16,24,...,64).
    private static final int[] PC1 = {
        57, 49, 41, 33, 25, 17,  9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    };

    /// Permuted Choice 2 (PC2) — selects 48 bits from the 56-bit shifted key
    /// halves to form each round subkey.
    private static final int[] PC2 = {
        14, 17, 11, 24,  1,  5,
         3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    /// Left-shift schedule — number of circular left-shift positions applied
    /// to each key half when generating the subkey for round i (1-indexed).
    private static final int[] SHIFTS = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    // =========================================================================
    // S-boxes  [8 boxes][4 rows][16 columns]
    // Row    = outer bits of the 6-bit group (bit 1 and bit 6) as a 2-bit int
    // Column = inner bits of the 6-bit group (bits 2-5) as a 4-bit int
    // =========================================================================

    private static final int[][][] S = {
        // S1
        {
            { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
            {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
            {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
            { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }
        },
        // S2
        {
            { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
            {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
            {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
            { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
        },
        // S3
        {
            { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
            { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
            { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
            {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
        },
        // S4
        {
            {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
            { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
            { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
            {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
        },
        // S5
        {
            {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
            { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
            {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
            { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
        },
        // S6
        {
            { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
            { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
            {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
            {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
        },
        // S7
        {
            {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
            { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
            {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
            {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
        },
        // S8
        {
            { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
            {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
            {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
            {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
        }
    };

    // =========================================================================
    // Helper utilities
    // =========================================================================

    /// Applies a permutation table to a bit array.
    /// @param block  source bit array (0/1 values, 0-indexed internally)
    /// @param table  1-indexed permutation table (e.g. IP, FP, E, P, ...)
    /// @return new bit array of length table.length with bits rearranged
    static int[] permute(int[] block, int[] table) {
        int[] out = new int[table.length];
        for (int i = 0; i < table.length; i++) {
            out[i] = block[table[i] - 1]; // convert 1-indexed to 0-indexed
        }
        return out;
    }

    /// XORs two equal-length bit arrays element-wise.
    static int[] xor(int[] a, int[] b) {
        int[] out = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = a[i] ^ b[i];
        }
        return out;
    }

    /// Counts the number of bit positions where two equal-length arrays differ.
    /// Used to compute the avalanche difference between two cipher states.
    static int countDiff(int[] a, int[] b) {
        int count = 0;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) count++;
        }
        return count;
    }

    /// Circular left-shift on a bit array of length 28 (one key half).
    /// @param half  28-bit key half
    /// @param n     number of positions to shift left
    static int[] leftShift(int[] half, int n) {
        int len = half.length;
        int[] out = new int[len];
        for (int i = 0; i < len; i++) {
            out[i] = half[(i + n) % len];
        }
        return out;
    }

    // =========================================================================
    // Key schedule
    // =========================================================================

    /// Checks that the supplied 64-bit key has correct odd parity:
    /// every 8th bit is a parity bit — each byte must have an odd number of 1s.
    /// Throws IllegalArgumentException if the key length or parity is wrong.
    static boolean checkKeyParity(int[] key) {
        if (key.length != 64) {
            throw new IllegalArgumentException("Key must be exactly 64 bits, got " + key.length);
        }

        // Check each of the 8 bytes independently
        for (int b = 0; b < 8; b++) {
            int ones = 0;
            // Sum the 8 bits in this byte
            for (int i = 0; i < 8; i++) {
                ones += key[b * 8 + i];
            }
            // Each byte must contain an odd number of 1-bits (odd parity)
            if (ones % 2 == 0) {
                throw new IllegalArgumentException("Key parity error in byte " + b);
            }
        }

        return true;
    }

    /// Generates the 16 round subkeys from a 64-bit key using PC1, PC2,
    /// and the left-shift schedule.
    /// @return int[16][48] — one 48-bit subkey per round (0-indexed, round 0 = round 1)
    static int[][] generateSubkeys(int[] key) {
        // Apply PC1 to select 56 bits from the 64-bit key (drops parity bits)
        int[] permutedKey = permute(key, PC1);

        // Split into two 28-bit halves
        int[] C = java.util.Arrays.copyOfRange(permutedKey, 0, 28);
        int[] D = java.util.Arrays.copyOfRange(permutedKey, 28, 56);

        int[][] subkeys = new int[16][48];
        for (int i = 0; i < 16; i++) {
            // Rotate each half left by the scheduled number of positions
            C = leftShift(C, SHIFTS[i]);
            D = leftShift(D, SHIFTS[i]);

            // Concatenate C and D, then apply PC2 to produce the 48-bit subkey
            int[] CD = new int[56];
            System.arraycopy(C, 0, CD, 0, 28);
            System.arraycopy(D, 0, CD, 28, 28);
            subkeys[i] = permute(CD, PC2);
        }
        return subkeys;
    }

    // =========================================================================
    // F-functions  (Liam — f0, f1; Guotai — f2, f3)
    // =========================================================================

    /// Applies all 8 S-boxes to a 48-bit input and returns a 32-bit output.
    /// Each 6-bit group maps to a 4-bit value via its S-box:
    ///   row = outer bits (bit 0 and bit 5), col = inner 4 bits (bits 1–4).
    /// @param block 48-bit input (e.g. result of XOR with subkey)
    /// @return 32-bit output (8 groups × 4 bits)
    private static int[] applySboxes(int[] block) {
        int[] result = new int[32];
        for (int i = 0; i < 8; i++) {
            int base = i * 6;
            int row = (block[base] << 1) | block[base + 5];          // outer bits
            int col = (block[base+1] << 3) | (block[base+2] << 2)
                    | (block[base+3] << 1) |  block[base+4];         // inner 4 bits
            int val = S[i][row][col];
            result[i*4]   = (val >> 3) & 1;
            result[i*4+1] = (val >> 2) & 1;
            result[i*4+2] = (val >> 1) & 1;
            result[i*4+3] =  val       & 1;
        }
        return result;
    }

    /// DES0 — standard F-function: E → XOR(subkey) → S-boxes → P
    static int[] f0(int[] R, int[] subkey) {
        int[] expanded  = permute(R, E);              // 32 → 48 bits
        int[] xored     = xor(expanded, subkey);      // mix in round key
        int[] sboxOut   = applySboxes(xored);         // 48 → 32 bits via S-boxes
        return permute(sboxOut, P);                   // diffusion
    }

    /// DES1 — XOR with round key is omitted: E → S-boxes → P
    static int[] f1(int[] R) {
        int[] expanded  = permute(R, E);              // 32 → 48 bits
        int[] sboxOut   = applySboxes(expanded);         // 48 → 32 bits via S-boxes
        return permute(sboxOut, P);
    }

    /// DES2 — S-boxes replaced by E⁻¹ (compress 48→32): E → XOR(subkey) → E⁻¹ → P
    static int[] f2(int[] R, int[] subkey) {
        int[] expanded   = permute(R, E);               // 32 → 48 bits
        int[] xored      = xor(expanded, subkey);       // mix in round key
        int[] contracted = permute(xored, E_INV);       // 48 → 32 bits (replaces S-boxes)
        return permute(contracted, P);                  // diffusion
    }

    /// DES3 — Permutation P is omitted: E → XOR(subkey) → S-boxes
    static int[] f3(int[] R, int[] subkey) {
        int[] expanded = permute(R, E);
        int[] xored    = xor(expanded, subkey);
        return applySboxes(xored);  // no permute(P) — that is the DES3 distinction
    }

    // =========================================================================
    // Encryption / Decryption  (Liam)
    // =========================================================================

    /// Encrypts a 64-bit plaintext block under the given key using DES variant
    /// 0–3 (selects the corresponding F-function).
    ///
    /// Returns int[17][64]: index 0 = state after IP (before round 1),
    /// indices 1–16 = full 64-bit block state after each Feistel round.
    /// This snapshot array is needed by Encryption.java for avalanche analysis.
    ///
    /// @param plaintext 64-bit plaintext as a bit array
    /// @param key       64-bit key as a bit array
    /// @param variant   0 = DES0, 1 = DES1, 2 = DES2, 3 = DES3
    static int[][] encrypt(int[] plaintext, int[] key, int variant) {
        int[][] subkeys   = generateSubkeys(key);
        int[][] snapshots = new int[17][64];

        // Apply IP and record pre-round state (Round 0)
        int[] block = permute(plaintext, IP);
        snapshots[0] = block;

        int[] L = java.util.Arrays.copyOfRange(block, 0, 32);
        int[] R = java.util.Arrays.copyOfRange(block, 32, 64);

        // 16 Feistel rounds, subkeys applied forward
        for (int i = 0; i < 16; i++) {
            int[] fOut;
            switch (variant) {
                case 1:  fOut = f1(R); break;
                case 2:  fOut = f2(R, subkeys[i]); break;
                case 3:  fOut = f3(R, subkeys[i]); break;
                default: fOut = f0(R, subkeys[i]); break;
            }
            int[] newR = xor(L, fOut);
            L = R;
            R = newR;

            // Snapshot intermediate L||R after this round
            System.arraycopy(L, 0, snapshots[i + 1], 0, 32);
            System.arraycopy(R, 0, snapshots[i + 1], 32, 32);
        }

        // Final swap (R before L) then FP — produces the ciphertext
        int[] combined = new int[64];
        System.arraycopy(R, 0, combined, 0, 32);
        System.arraycopy(L, 0, combined, 32, 32);
        snapshots[16] = permute(combined, FP);

        return snapshots;
    }

    /// Decrypts a 64-bit ciphertext block under the given key (standard DES0).
    /// Applies subkeys in reverse order (round 16 → round 1).
    ///
    /// @param ciphertext 64-bit ciphertext as a bit array
    /// @param key        64-bit key as a bit array
    /// @return 64-bit plaintext as a bit array
    static int[] decrypt(int[] ciphertext, int[] key) {
        int[][] subkeys = generateSubkeys(key);

        // Apply initial permutation
        int[] block = permute(ciphertext, IP);

        // Split into left and right halves
        int[] L = java.util.Arrays.copyOfRange(block, 0, 32);
        int[] R = java.util.Arrays.copyOfRange(block, 32, 64);

        // 16 Feistel rounds with subkeys in reverse order
        for (int i = 0; i < 16; i++) {
            int[] newR = xor(L, f0(R, subkeys[15 - i]));
            L = R;
            R = newR;
        }

        // Combine halves with final swap (R before L), then apply final permutation
        int[] combined = new int[64];
        System.arraycopy(R, 0, combined, 0, 32);
        System.arraycopy(L, 0, combined, 32, 32);
        return permute(combined, FP);
    }
}
