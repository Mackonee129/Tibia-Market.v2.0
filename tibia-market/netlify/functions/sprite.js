// Netlify Function — proxy de imágenes para sprites de TibiaWiki.
// El navegador a veces no carga el hotlink directo a Fandom (protección
// anti-bot / hotlink). Esta función descarga la imagen del lado servidor
// con un User-Agent de navegador y la reenvía cacheada, evitando ese bloqueo.
//
// Uso desde el front:  /.netlify/functions/sprite?name=Sanguine%20Blade
exports.handler = async (event) => {
  const raw = event.queryStringParameters?.name;
  if (!raw) {
    return { statusCode: 400, body: "Falta el parámetro name" };
  }

  // "Sanguine Blade" -> "Sanguine_Blade" (slug de página de TibiaWiki)
  const slug = encodeURIComponent(raw.trim().replace(/\s+/g, "_"));
  const url = `https://tibia.fandom.com/wiki/Special:FilePath/${slug}.gif`;

  try {
    const res = await fetch(url, {
      redirect: "follow",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
          "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "image/avif,image/webp,image/gif,image/*,*/*;q=0.8",
      },
    });

    if (!res.ok) {
      return { statusCode: res.status, body: "" };
    }

    const buf = Buffer.from(await res.arrayBuffer());
    return {
      statusCode: 200,
      headers: {
        "Content-Type": res.headers.get("content-type") || "image/gif",
        // cache agresivo: los sprites de items casi nunca cambian
        "Cache-Control": "public, max-age=604800, immutable",
        "Access-Control-Allow-Origin": "*",
      },
      body: buf.toString("base64"),
      isBase64Encoded: true,
    };
  } catch (err) {
    return { statusCode: 502, body: "Error al obtener el sprite: " + err.message };
  }
};
