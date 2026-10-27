// Netlify Function — proxy para TibiaData API
// Evita CORS desde el browser llamando server-to-server
exports.handler = async (event) => {
  const name = event.queryStringParameters?.name;
  if (!name) {
    return { statusCode: 400, body: JSON.stringify({ error: "Falta el parámetro name" }) };
  }
  // Validar: solo letras, números, espacios y apóstrofes (nombres válidos de Tibia)
  if (!/^[a-zA-Z0-9 \'\-]{1,50}$/.test(name.trim())) {
    return { statusCode: 400, body: JSON.stringify({ error: "Nombre de personaje inválido" }) };
  }

  try {
    const url = `https://api.tibiadata.com/v4/character/${encodeURIComponent(name)}`;
    const res  = await fetch(url, { headers: { "Accept": "application/json" } });
    const data = await res.json();

    return {
      statusCode: res.status,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
      body: JSON.stringify(data),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Error al consultar TibiaData: " + err.message }),
    };
  }
};
