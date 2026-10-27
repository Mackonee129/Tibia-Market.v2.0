// Netlify Function — sirve sprites de items de TibiaWiki desde TU dominio.
// Usa la URL canónica de TibiaWiki (Special:Redirect/file) que redirige al
// archivo real; la función sigue el redirect del lado servidor (sin bloqueos
// de referrer/CORP del navegador) y reenvía la imagen cacheada.
//
// Uso:  /.netlify/functions/sprite?name=Sanguine%20Blade
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36";

exports.handler = async (event) => {
  const raw = event.queryStringParameters && event.queryStringParameters.name;
  if (!raw) return { statusCode: 400, body: "Falta el parámetro name" };

  const slug = encodeURIComponent(raw.trim().replace(/\s+/g, "_"));
  const url = `https://tibia.fandom.com/wiki/Special:Redirect/file/${slug}.gif`;

  try {
    const res = await fetch(url, {
      redirect: "follow",
      headers: { "User-Agent": UA, Accept: "image/avif,image/webp,image/gif,image/*,*/*;q=0.8" },
    });
    if (!res.ok) return { statusCode: res.status, body: "" };
    const ct = res.headers.get("content-type") || "";
    if (!ct.startsWith("image/")) return { statusCode: 404, body: "" };
    const buf = Buffer.from(await res.arrayBuffer());
    return {
      statusCode: 200,
      headers: {
        "Content-Type": ct || "image/gif",
        "Cache-Control": "public, max-age=31536000, immutable",
        "Access-Control-Allow-Origin": "*",
      },
      body: buf.toString("base64"),
      isBase64Encoded: true,
    };
  } catch (err) {
    return { statusCode: 502, body: "" };
  }
};
