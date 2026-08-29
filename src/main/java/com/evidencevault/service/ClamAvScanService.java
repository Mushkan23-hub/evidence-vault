package com.evidencevault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Talks directly to a clamd daemon over TCP using its INSTREAM protocol - no external client
 * library needed (this project's build environment can't reach arbitrary Maven repos, and the
 * protocol itself is simple enough not to need one).
 *
 * INSTREAM protocol: send "zINSTREAM\0", then the file in chunks each prefixed by a 4-byte
 * big-endian length, then a zero-length chunk to signal EOF, then read clamd's reply. A clean
 * file replies "stream: OK"; an infected file replies "stream: <SIGNATURE_NAME> FOUND".
 *
 * DEPLOYMENT NOTE: this requires a clamd daemon reachable at evidencevault.clamav.host:port.
 * That daemon is external infrastructure (a ClamAV container, or a Kali/Linux clamav-daemon
 * install) - see the docker-compose.yml clamav service and README for setup steps. This class
 * only implements the CLIENT side; if evidencevault.clamav.enabled=false (the default), scanning
 * is skipped entirely and uploads proceed unscanned, so the app runs fine without ClamAV present.
 */
@Service
public class ClamAvScanService {

    private static final int CHUNK_SIZE = 4096;
    private static final int SOCKET_TIMEOUT_MS = 15_000;

    private final boolean enabled;
    private final String host;
    private final int port;

    public ClamAvScanService(
            @Value("${evidencevault.clamav.enabled:false}") boolean enabled,
            @Value("${evidencevault.clamav.host:localhost}") String host,
            @Value("${evidencevault.clamav.port:3310}") int port) {
        this.enabled = enabled;
        this.host = host;
        this.port = port;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public record ScanResult(boolean clean, String detail) {}

    /**
     * Scans the given bytes. If scanning is disabled (no ClamAV configured), always returns
     * clean=true so uploads aren't blocked when the daemon isn't set up. If scanning is enabled
     * but the daemon is unreachable, this FAILS CLOSED (clean=false) rather than silently letting
     * unscanned files through - a misconfigured/down scanner shouldn't be indistinguishable from
     * "file is clean".
     */
    public ScanResult scan(byte[] data) {
        if (!enabled) {
            return new ScanResult(true, "ClamAV scanning disabled - upload not scanned");
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), SOCKET_TIMEOUT_MS);
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeBytes("zINSTREAM\0");

            int offset = 0;
            while (offset < data.length) {
                int len = Math.min(CHUNK_SIZE, data.length - offset);
                out.writeInt(len); // 4-byte big-endian length prefix, per protocol
                out.write(data, offset, len);
                offset += len;
            }
            out.writeInt(0); // zero-length chunk signals EOF
            out.flush();

            String response = readResponse(socket.getInputStream());
            if (response.contains("FOUND")) {
                return new ScanResult(false, response.trim());
            }
            if (response.contains("OK")) {
                return new ScanResult(true, response.trim());
            }
            // Unexpected response (protocol error, daemon misbehaving) - fail closed
            return new ScanResult(false, "Unexpected ClamAV response: " + response.trim());

        } catch (IOException e) {
            // Daemon unreachable/misconfigured - fail closed rather than pretend the file is clean
            return new ScanResult(false, "ClamAV daemon unreachable (" + host + ":" + port + "): " + e.getMessage());
        }
    }

    private String readResponse(InputStream in) throws IOException {
        byte[] buf = new byte[512];
        int read = in.read(buf);
        return read > 0 ? new String(buf, 0, read, StandardCharsets.UTF_8) : "";
    }
}
