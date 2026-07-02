/**
 * ClamAV malware scanning via clamd's INSTREAM protocol, implemented directly over a raw TCP
 * socket (no external npm wrapper) - talks to any clamd instance (local install, Docker sidecar,
 * or a remote clamd) reachable at CLAMAV_HOST:CLAMAV_PORT.
 *
 * If clamd isn't reachable (not installed, not running, wrong host/port), this degrades
 * gracefully to status "unavailable" rather than failing the whole upload/scan pipeline - the
 * rest of the threat pipeline (magic bytes, hashes, VirusTotal, risk engine) still runs.
 *
 * Protocol reference: https://docs.clamav.net/manual/Usage/Scanning.html#stream-scan (INSTREAM)
 */
import net from "net";

const DEFAULT_HOST = process.env.CLAMAV_HOST || "127.0.0.1";
const DEFAULT_PORT = parseInt(process.env.CLAMAV_PORT) || 3310;
const CHUNK_SIZE = 64 * 1024;
const CONNECT_TIMEOUT_MS = 3000;
const SCAN_TIMEOUT_MS = 15000;

/**
 * @param {Buffer} buffer - plaintext file bytes to scan (never persisted to disk)
 * @returns {Promise<{status: "clean"|"infected"|"error"|"unavailable", threatNames: string[], engineVersion?: string}>}
 */
export async function scanBufferWithClamAV(buffer) {
  try {
    const response = await streamToClamd(buffer);
    return parseClamdResponse(response);
  } catch (err) {
    // ECONNREFUSED / timeout / any transport failure = clamd not available in this environment.
    // This is expected in sandboxes/dev environments without ClamAV installed - not a hard error.
    return { status: "unavailable", threatNames: [], error: err.message };
  }
}

function streamToClamd(buffer) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let response = "";
    let settled = false;

    const fail = (err) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };
    const succeed = (data) => {
      if (settled) return;
      settled = true;
      resolve(data);
    };

    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.once("timeout", () => fail(new Error("clamd connection timed out")));
    socket.once("error", (err) => fail(err));

    socket.connect(DEFAULT_PORT, DEFAULT_HOST, () => {
      socket.setTimeout(SCAN_TIMEOUT_MS);
      socket.write("zINSTREAM\0");

      for (let offset = 0; offset < buffer.length; offset += CHUNK_SIZE) {
        const chunk = buffer.subarray(offset, Math.min(offset + CHUNK_SIZE, buffer.length));
        const lengthPrefix = Buffer.alloc(4);
        lengthPrefix.writeUInt32BE(chunk.length, 0);
        socket.write(lengthPrefix);
        socket.write(chunk);
      }
      // Zero-length chunk signals end of stream, per the INSTREAM protocol.
      const endMarker = Buffer.alloc(4);
      endMarker.writeUInt32BE(0, 0);
      socket.write(endMarker);
    });

    socket.on("data", (data) => {
      response += data.toString("utf8");
    });

    socket.on("end", () => succeed(response));
    socket.on("close", () => succeed(response));
  });
}

function parseClamdResponse(response) {
  const clean = response.replace(/\0/g, "").trim();
  // Typical responses: "stream: OK" or "stream: Eicar-Test-Signature FOUND"
  if (/OK$/.test(clean)) {
    return { status: "clean", threatNames: [] };
  }
  const foundMatch = /stream:\s*(.+?)\s+FOUND$/.exec(clean);
  if (foundMatch) {
    return { status: "infected", threatNames: [foundMatch[1]] };
  }
  if (/ERROR/i.test(clean)) {
    return { status: "error", threatNames: [], error: clean };
  }
  return { status: "error", threatNames: [], error: `Unrecognized clamd response: ${clean}` };
}
