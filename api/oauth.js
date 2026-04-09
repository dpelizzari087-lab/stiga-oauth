const express = require("express");
const { v4: uuidv4 } = require("uuid");
const fetch = require("node-fetch");

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.text({ type: "*/*" }));

const CLIENT_ID = "stiga-client-id";
const CLIENT_SECRET = "stiga-client-secret";

const loginPage = `
<!DOCTYPE html>
<html>
  <head><meta charset="UTF-8"><title>Login Stiga</title></head>
  <body>
    <h2>Accedi al tuo account Stiga</h2>
    <form method="POST" action="/api/login">
      <input type="hidden" name="redirect_uri" value="{{redirect_uri}}" />
      <input type="hidden" name="state" value="{{state}}" />
      <input type="hidden" name="client_id" value="{{client_id}}" />

      <label>Email:</label><br/>
      <input type="email" name="email" required /><br/><br/>

      <label>Password:</label><br/>
      <input type="password" name="password" required /><br/><br/>

      <button type="submit">Accedi</button>
    </form>
  </body>
</html>
`;

const authCodes = {};

app.get("/api/authorize", (req, res) => {
  const { client_id, redirect_uri, state, response_type } = req.query;

  if (client_id !== CLIENT_ID || response_type !== "code") {
    return res.status(400).send("Invalid client_id or response_type");
  }

  const page = loginPage
    .replace("{{redirect_uri}}", redirect_uri)
    .replace("{{state}}", state || "")
    .replace("{{client_id}}", client_id);

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page);
});

app.post("/api/login", async (req, res) => {
  const { email, password, redirect_uri, state, client_id } = req.body;

  if (client_id !== CLIENT_ID) {
    return res.status(400).send("Invalid client_id");
  }

  try {
    const firebaseUrl =
      "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=AIzaSyCPtRBU_hwWZYsguHp9ucGrfNac0kXR6ug";

    const firebaseResponse = await fetch(firebaseUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        password,
        returnSecureToken: true
      })
    });

    const data = await firebaseResponse.json();

    if (!firebaseResponse.ok) {
      return res.status(401).send("Credenziali non valide");
    }

    const idToken = data.idToken;

    const code = uuidv4();
    authCodes[code] = {
      token: idToken,
      createdAt: Date.now()
    };

    if (!redirect_uri) {
  return res.status(400).send("Missing redirect_uri");
}

try {
  const decodedRedirect = decodeURIComponent(redirect_uri);
  const url = new URL(decodedRedirect);

  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);

  res.redirect(url.toString());
} catch (e) {
  console.error("Redirect URI error:", e);
  return res.status(400).send("Invalid redirect_uri");
}
  } catch (err) {
    console.error(err);
    res.status(500).send("Errore interno");
  }
});

app.post("/api/token", (req, res) => {
  console.log("TOKEN RAW BODY:", req.body);
  console.log("TOKEN HEADERS:", req.headers);
  let body = req.body;

  if (typeof body === "string") {
    body = Object.fromEntries(new URLSearchParams(body));
  }

  const { grant_type, code, client_id, client_secret } = body;

  if (client_id !== CLIENT_ID || client_secret !== CLIENT_SECRET) {
    return res.status(400).json({ error: "invalid_client" });
  }

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  const authData = authCodes[code];
  if (!authData) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  const accessToken = authData.token;

  delete authCodes[code];

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600
  });
});

module.exports = (req, res) => app(req, res);
