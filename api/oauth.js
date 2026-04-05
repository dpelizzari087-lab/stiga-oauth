const express = require("express");
const bodyParser = require("body-parser");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const authCodes = {};
const accessTokens = {};

const CLIENT_ID = "stiga-client-id";
const CLIENT_SECRET = "stiga-client-secret";

const loginPage = `
<!DOCTYPE html>
<html>
  <head><meta charset="UTF-8"><title>Login Stiga</title></head>
  <body>
    <h2>Login Stiga (demo)</h2>
    <form method="POST" action="/api/login">
      <input type="hidden" name="redirect_uri" value="{{redirect_uri}}" />
      <input type="hidden" name="state" value="{{state}}" />
      <input type="hidden" name="client_id" value="{{client_id}}" />
      <label>Email:</label><br/>
      <input type="text" name="email" /><br/>
      <label>Password:</label><br/>
      <input type="password" name="password" /><br/><br/>
      <button type="submit">Accedi</button>
    </form>
  </body>
</html>
`;

app.get("/authorize", (req, res) => {
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

app.post("/login", (req, res) => {
  const { email, password, redirect_uri, state, client_id } = req.body;

  if (!email || !password) {
    return res.status(400).send("Credenziali mancanti");
  }

  if (client_id !== CLIENT_ID) {
    return res.status(400).send("Invalid client_id");
  }

  const code = uuidv4();

  authCodes[code] = {
    userId: email,
    createdAt: Date.now()
  };

  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);

  res.redirect(url.toString());
});

app.post("/token", (req, res) => {
  const {
    grant_type,
    code,
    client_id,
    client_secret
  } = req.body;

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

  const accessToken = uuidv4();
  accessTokens[accessToken] = {
    userId: authData.userId,
    createdAt: Date.now()
  };

  delete authCodes[code];

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: uuidv4()
  });
});

module.exports = app;
