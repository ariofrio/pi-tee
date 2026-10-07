import assert from "node:assert/strict";
import { createServer } from "node:https";
import { readFile } from "node:fs/promises";

const [certificate, privateKey] = process.argv.slice(2);
let requests = 0;
const server = createServer({ cert: await readFile(certificate), key: await readFile(privateKey) }, (req, res) => {
  const id = ++requests;
  assert.equal(req.headers.authorization, "Bearer synthetic-key");
  let body = "";
  req.on("data", chunk => { body += chunk; });
  req.on("end", () => {
    assert.equal(body, "synthetic payload");
    console.log(JSON.stringify({ request: id }));
    if (req.headers["x-synthetic-mode"] === "redirect") {
      res.writeHead(307, { location: "https://must-never-connect.invalid/" }); res.end("redirect");
    } else if (req.headers["x-synthetic-mode"] === "drop") {
      req.socket.destroy();
    } else if (req.headers["x-synthetic-mode"] === "stream") {
      res.writeHead(200); res.write("first delta");
      res.on("close", () => console.log(JSON.stringify({ closed: id })));
    } else { res.writeHead(200); res.end("complete"); }
  });
});
server.listen(0, "127.0.0.1", () => console.log(JSON.stringify({ port: server.address().port })));
