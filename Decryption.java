/// Decryption.java
///
/// Entry point for DES decryption.
/// Reads a 64-bit ciphertext and a 64-bit key from an input file, decrypts
/// using standard DES (DES0), and writes the result to an output file.
///
/// Usage:  java Decryption <input_file>
/// Output: output.txt
///
/// Authors: Guotai Xiao (3501343), Liam Anderson (3404752)
/// Course:  COMP3260 Data Security, Assignment 2

import java.io.*;
import java.util.Scanner;

public class Decryption {

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: java Decryption <input_file>");
            return;
        }

        // ── Read input file ───────────────────────────────────────────────────
        // Expected format (one 64-bit binary string per line):
        //   Line 1: ciphertext C
        //   Line 2: key K
        Scanner sc = new Scanner(new File(args[0]));
        int[] C = parseBits(sc.nextLine().trim());
        int[] K = parseBits(sc.nextLine().trim());
        sc.close();

        // ── Decrypt ───────────────────────────────────────────────────────────
        int[] plaintext = DES.decrypt(C, K);

        // ── Write output file ─────────────────────────────────────────────────
        PrintWriter out = new PrintWriter(new FileWriter("output.txt"));

        out.println("DECRYPTION");
        out.println("Ciphertext C: " + bitsToString(C));
        out.println("Key K: "        + bitsToString(K));
        out.println("Plaintext P: "  + bitsToString(plaintext));

        out.close();
        System.out.println("Done. Results written to output.txt");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Converts a 64-character binary string ("010011...") to an int[] of 0s and 1s.
    private static int[] parseBits(String s) {
        int[] bits = new int[s.length()];
        for (int i = 0; i < s.length(); i++) {
            bits[i] = s.charAt(i) - '0';
        }
        return bits;
    }

    /// Converts an int[] of 0s and 1s back to a binary string.
    private static String bitsToString(int[] bits) {
        StringBuilder sb = new StringBuilder(bits.length);
        for (int b : bits) sb.append(b);
        return sb.toString();
    }
}
