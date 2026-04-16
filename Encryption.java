/// Encryption.java
///
/// Entry point for DES encryption and avalanche effect analysis.
/// Reads four 64-bit binary strings from an input file (P, P', K, K'),
/// encrypts using all four DES variants (DES0–DES3), and writes a formatted
/// output file showing ciphertexts and per-round bit differences.
///
/// Usage:  java Encryption <input_file>
/// Output: output.txt
///
/// Authors: Guotai Xiao (3501343), Liam Anderson (3404752)
/// Course:  COMP3260 Data Security, Assignment 2

import java.io.*;
import java.util.Scanner;

public class Encryption {

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: java Encryption <input_file>");
            return;
        }

        // ── Read input file ───────────────────────────────────────────────────
        // Expected format (one 64-bit binary string per line):
        //   Line 1: plaintext P
        //   Line 2: plaintext P'
        //   Line 3: key K
        //   Line 4: key K'
        Scanner sc = new Scanner(new File(args[0]));
        int[] P  = parseBits(sc.nextLine().trim());
        int[] Pp = parseBits(sc.nextLine().trim());
        int[] K  = parseBits(sc.nextLine().trim());
        int[] Kp = parseBits(sc.nextLine().trim());
        sc.close();

        long startTime = System.nanoTime();

        // ── Encrypt with all 4 variants ───────────────────────────────────────
        // Each call returns int[17][64]: index 0 = state after IP, 1-16 = after each round.
        // Section 1: P and P' under K
        int[][][] statesPK  = new int[4][][]; // statesPK[variant]  = encrypt(P,  K, variant)
        int[][][] statesPpK = new int[4][][]; // statesPpK[variant] = encrypt(P', K, variant)
        // Section 2: P under K and K'
        int[][][] statesPKp = new int[4][][]; // statesPKp[variant] = encrypt(P, K', variant)

        for (int v = 0; v < 4; v++) {
            statesPK[v]  = DES.encrypt(P,  K,  v);
            statesPpK[v] = DES.encrypt(Pp, K,  v);
            statesPKp[v] = DES.encrypt(P,  Kp, v);
        }

        long endTime = System.nanoTime();
        double elapsedSeconds = (endTime - startTime) / 1_000_000_000.0;

        // ── Write output file ─────────────────────────────────────────────────
        PrintWriter out = new PrintWriter(new FileWriter("output.txt"));

        out.println("Avalanche Demonstration");
        out.println("Plaintext P:  " + bitsToString(P));
        out.println("Plaintext P': " + bitsToString(Pp));
        out.println("Key K:  "       + bitsToString(K));
        out.println("Key K': "       + bitsToString(Kp));
        out.printf ("Total running time: %.6f (second)%n", elapsedSeconds);
        out.println();

        // Section 1 — P and P' encrypted under K
        out.println("P and P' under K");
        // Ciphertexts are the final state (round 16) of DES0
        out.println("Ciphertext C:  " + bitsToString(statesPK[0][16]));
        out.println("Ciphertext C': " + bitsToString(statesPpK[0][16]));
        out.println(roundTableHeader());
        for (int round = 0; round <= 16; round++) {
            out.println(roundTableRow(round,
                DES.countDiff(statesPK[0][round], statesPpK[0][round]),
                DES.countDiff(statesPK[1][round], statesPpK[1][round]),
                DES.countDiff(statesPK[2][round], statesPpK[2][round]),
                DES.countDiff(statesPK[3][round], statesPpK[3][round])
            ));
        }
        out.println();

        // Section 2 — P encrypted under K vs K'
        out.println("P under K and K'");
        out.println("Ciphertext C:  " + bitsToString(statesPK[0][16]));
        out.println("Ciphertext C': " + bitsToString(statesPKp[0][16]));
        out.println(roundTableHeader());
        for (int round = 0; round <= 16; round++) {
            out.println(roundTableRow(round,
                DES.countDiff(statesPK[0][round], statesPKp[0][round]),
                DES.countDiff(statesPK[1][round], statesPKp[1][round]),
                DES.countDiff(statesPK[2][round], statesPKp[2][round]),
                DES.countDiff(statesPK[3][round], statesPKp[3][round])
            ));
        }

        out.close();
        System.out.println("Done. Results written to output.txt");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Converts a 64-character binary string ("010011...") to an int[] of 0s and 1s.
    private static int[] parseBits(String s) {
        int[] bits = new int[s.length()];
        for (int i = 0; i < s.length(); i++) {
            bits[i] = s.charAt(i) - '0'; // '0' → 0, '1' → 1
        }
        return bits;
    }

    /// Converts an int[] of 0s and 1s back to a binary string.
    private static String bitsToString(int[] bits) {
        StringBuilder sb = new StringBuilder(bits.length);
        for (int b : bits) sb.append(b);
        return sb.toString();
    }

    /// Returns the header row for the round difference table.
    private static String roundTableHeader() {
        return String.format("%-8s%-8s%-8s%-8s%-8s", "Round", "DES0", "DES1", "DES2", "DES3");
    }

    /// Returns one data row for the round difference table.
    private static String roundTableRow(int round, int d0, int d1, int d2, int d3) {
        return String.format("%-8d%-8d%-8d%-8d%-8d", round, d0, d1, d2, d3);
    }
}
