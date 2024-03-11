import { fileURLToPath } from "url";
import { dirname } from "path";
import fs from "fs";
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();
const PORT = 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const privateKeyPath = `${__dirname}/../config/my.rsa.privatekey.pem`;
const publicKeyPath = `${__dirname}/../config/my.rsa.publickey.pem`;

const privateKey = fs.readFileSync(privateKeyPath, "utf-8");
const publicKey = fs.readFileSync(publicKeyPath, "utf-8");

app.use(bodyParser.json());

app.post("/encrypt", (req, res) => {
  const plainText = req.body.text;
  const encryptedMessage = crypto.publicEncrypt(
    {
      key: publicKey,
      passphrase: "",
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    Buffer.from(plainText)
  );
  res.send({ encryptedMessage: encryptedMessage.toString("base64") });
});

app.post("/decrypt", (req, res) => {
  const encryptedText = req.body.encryptedText;
  const decryptedMessage = crypto.privateDecrypt(
    {
      key: privateKey,
      passphrase: "",
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    Buffer.from(encryptedText, "base64")
  );
  res.send({ decryptedMessage: decryptedMessage.toString("utf8") });
});

app.post("/sign", (req, res) => {
  const plainText = req.body.text;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(plainText);
  const signature = signer.sign(privateKey, "hex");
  res.send({ signature });
});

app.post("/verify", (req, res) => {
  const plainText = req.body.text;
  const signature = req.body.signature;
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(plainText);
  const isValid = verifier.verify(publicKey, signature, "hex");
  res.send({ isValid });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
