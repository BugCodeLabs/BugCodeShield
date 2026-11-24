const express = require("express");
const app = express();

// Intentionally unsafe sample for scanner tests. Do not deploy.
const stripeKey = "sk_live_51ExampleExampleExampleExampleExample0001";

app.get("/search", (req, res) => {
  const q = req.query.q;
  eval("result = " + q);
  res.send(String(result));
});

app.listen(3000);
