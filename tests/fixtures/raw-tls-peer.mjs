// Synthetic TLS peer for pinned-tls tests, always run under Node so its TLS
// version and write backpressure behave the same for Node and Bun clients.
// Usage: node raw-tls-peer.mjs <cert> <key> <maxVersion> <mode> [base64 response]
// Prints the listening port, then "written <bytes>" lines in flood mode.
import { readFileSync } from "node:fs";
import { createServer } from "node:tls";

const [cert, key, maxVersion, mode, response] = process.argv.slice(2);
const server = createServer({ cert: readFileSync(cert), key: readFileSync(key), maxVersion }, socket => {
  let request = Buffer.alloc(0);
  let answered = false;
  socket.on("error", () => {});
  socket.on("data", chunk => {
    request = Buffer.concat([request, chunk]);
    if (answered || !request.includes("\r\n\r\nsynthetic")) return;
    answered = true;
    if (mode === "raw") return void socket.end(Buffer.from(response, "base64"));
    socket.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    const piece = Buffer.alloc(1024 * 1024, 120);
    const frame = Buffer.concat([Buffer.from(piece.length.toString(16) + "\r\n"), piece, Buffer.from("\r\n")]);
    let written = 0;
    const report = setInterval(() => console.log(`written ${written}`), 100);
    socket.on("close", () => { clearInterval(report); console.log(`written ${written}`); });
    const pump = () => {
      while (written < 256 * 1024 * 1024) {
        written += piece.length;
        if (!socket.write(frame)) return void socket.once("drain", pump);
      }
    };
    pump();
  });
});
server.listen(0, "127.0.0.1", () => console.log(server.address().port));
