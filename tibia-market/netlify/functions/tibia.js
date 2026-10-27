// Netlify Function — proxy para TibiaData API
// Evita CORS desde el browser llamando server-to-server
exports.handler = async (event) => {
  const name = event.queryStringParameters?.name;
  if (!name) {
    return { statusCode: 400, body: JSON.stringify({ error: "Falta el parámetro name" }) };
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
