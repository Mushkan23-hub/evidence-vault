package com.evidencevault.service;

import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Lightweight forensic analysis utilities implemented entirely in Java, deliberately
 * without shelling out to external tools (file, strings, xxd, etc.) - this keeps the
 * app fully self-contained and portable across any deployment target, since a deployed
 * server has no access to tools installed on a developer's own machine.
 */
@Service
public class ForensicAnalysisService {

    /** Known file signatures ("magic bytes"), checked in order, most specific first. */
    private static final List<Signature> SIGNATURES = List.of(
            new Signature("PDF Document", hex("255044462D"), Set.of("pdf")),
            new Signature("PNG Image", hex("89504E470D0A1A0A"), Set.of("png")),
            new Signature("JPEG Image", hex("FFD8FF"), Set.of("jpg", "jpeg")),
            new Signature("GIF Image (87a)", hex("474946383761"), Set.of("gif")),
            new Signature("GIF Image (89a)", hex("474946383961"), Set.of("gif")),
            new Signature("RAR Archive", hex("526172211A0700"), Set.of("rar")),
            new Signature("ZIP-based Archive (zip/docx/xlsx/jar/apk)", hex("504B0304"), Set.of("zip", "docx", "xlsx", "pptx", "jar", "apk")),
            new Signature("GZIP Archive", hex("1F8B"), Set.of("gz", "tgz")),
            new Signature("BZIP2 Archive", hex("425A68"), Set.of("bz2")),
            new Signature("ELF Executable (Linux)", hex("7F454C46"), Set.of("elf", "so", "bin")),
            new Signature("Windows Executable (EXE/DLL)", hex("4D5A"), Set.of("exe", "dll")),
            new Signature("XML Document", "<?xml".getBytes(), Set.of("xml", "xhtml", "svg")),
            new Signature("SQLite Database", "SQLite format 3\u0000".getBytes(), Set.of("db", "sqlite", "sqlite3"))
    );

    public FileTypeResult detectFileType(byte[] data, String claimedFilename, String claimedContentType) {
        String detected = "Unknown Binary";
        String signatureHex = "";
        Set<String> expectedExtensions = Set.of();

        for (Signature sig : SIGNATURES) {
            if (startsWith(data, sig.magic)) {
                detected = sig.label;
                signatureHex = toHex(Arrays.copyOf(sig.magic, Math.min(sig.magic.length, 8)));
                expectedExtensions = sig.extensions;
                break;
            }
        }

        if (detected.equals("Unknown Binary") && isLikelyPlainText(data)) {
            detected = "Plain Text";
            expectedExtensions = Set.of("txt", "csv", "log", "md", "json", "yml", "yaml", "conf");
        }

        String claimedExt = extractExtension(claimedFilename);
        boolean mismatch = !expectedExtensions.isEmpty()
                && !claimedExt.isEmpty()
                && !expectedExtensions.contains(claimedExt.toLowerCase());

        return new FileTypeResult(detected, claimedContentType, claimedExt, mismatch, signatureHex);
    }

    /** Classic hex-dump format: offset, 16 hex bytes, ASCII representation. Capped to avoid huge payloads. */
    public List<String> hexDump(byte[] data, int maxBytes) {
        int limit = Math.min(data.length, maxBytes);
        List<String> lines = new ArrayList<>();
        for (int offset = 0; offset < limit; offset += 16) {
            StringBuilder hexPart = new StringBuilder();
            StringBuilder asciiPart = new StringBuilder();
            int rowEnd = Math.min(offset + 16, limit);
            for (int i = offset; i < rowEnd; i++) {
                hexPart.append(String.format("%02X ", data[i]));
                char c = (char) (data[i] & 0xFF);
                asciiPart.append(c >= 32 && c < 127 ? c : '.');
            }
            lines.add(String.format("%08X  %-48s  %s", offset, hexPart, asciiPart));
        }
        return lines;
    }

    /** Extracts printable ASCII runs of at least minLength, like the Unix `strings` command. */
    public StringsResult extractStrings(byte[] data, int minLength, int maxResults) {
        List<String> found = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        int totalMatches = 0;

        for (byte b : data) {
            char c = (char) (b & 0xFF);
            if (c >= 32 && c < 127) {
                current.append(c);
            } else {
                if (current.length() >= minLength) {
                    totalMatches++;
                    if (found.size() < maxResults) found.add(current.toString());
                }
                current.setLength(0);
            }
        }
        if (current.length() >= minLength) {
            totalMatches++;
            if (found.size() < maxResults) found.add(current.toString());
        }

        return new StringsResult(found, totalMatches, totalMatches > found.size());
    }

    private boolean isLikelyPlainText(byte[] data) {
        int sample = Math.min(data.length, 512);
        if (sample == 0) return true;
        int printable = 0;
        for (int i = 0; i < sample; i++) {
            int b = data[i] & 0xFF;
            if ((b >= 32 && b < 127) || b == 9 || b == 10 || b == 13) printable++;
        }
        return (double) printable / sample > 0.95;
    }

    private String extractExtension(String filename) {
        if (filename == null) return "";
        int dot = filename.lastIndexOf('.');
        return dot == -1 || dot == filename.length() - 1 ? "" : filename.substring(dot + 1);
    }

    private boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }

    private static byte[] hex(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }
        return out;
    }

    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X ", b));
        return sb.toString().trim();
    }

    private record Signature(String label, byte[] magic, Set<String> extensions) {}

    public record FileTypeResult(String detectedType, String claimedContentType, String claimedExtension,
                                  boolean mismatch, String signatureHex) {}

    public record StringsResult(List<String> strings, int totalFound, boolean truncated) {}
}
