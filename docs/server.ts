/**
 * Tiny static file server for sibl docs.
 * Works with Deno (recommended) or Bun.
 *
 * Usage:
 *   deno run --allow-net --allow-read serve-docs.ts
 *   bun run serve-docs.ts
 *
 * Serves the ./docs directory (or pass a path as first arg).
 */

const root = Deno.args[0] ?? "./docs";
const port = Number(Deno.env.get("PORT") ?? "8000");

const server = Deno.serve({ port }, async (req) => {
  const url = new URL(req.url);
  let path = decodeURIComponent(url.pathname);

  if (path === "/" || path === "") {
    path = "/index.html";
  }

  // Prevent directory traversal
  const filePath = `${root}${path}`.replace(/\/+/g, "/");
  if (filePath.includes("..")) {
    return new Response("Forbidden", { status: 403 });
  }

  try {
    const file = await Deno.open(filePath, { read: true });
    const stat = await file.stat();

    if (stat.isDirectory) {
      file.close();
      // Try index.html inside directory
      return new Response(null, {
        status: 302,
        headers: { Location: path.endsWith("/") ? `${path}index.html` : `${path}/` },
      });
    }

    const headers = new Headers();
    const ext = filePath.split(".").pop()?.toLowerCase();

    switch (ext) {
      case "html":
        headers.set("content-type", "text/html; charset=utf-8");
        break;
      case "js":
        headers.set("content-type", "text/javascript; charset=utf-8");
        break;
      case "wasm":
        headers.set("content-type", "application/wasm");
        break;
      case "tar":
        headers.set("content-type", "application/x-tar");
        break;
      case "css":
        headers.set("content-type", "text/css; charset=utf-8");
        break;
      case "json":
        headers.set("content-type", "application/json");
        break;
      default:
        headers.set("content-type", "application/octet-stream");
    }

    headers.set("content-length", String(stat.size));
    headers.set("cache-control", "no-cache");

    return new Response(file.readable, { headers });
  } catch {
    return new Response("Not Found", { status: 404 });
  }
});

console.log(`Serving ${root} at http://localhost:${port}`);
console.log("Press Ctrl+C to stop");

