import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import 'dotenv/config';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 8787;
const HOST = process.env.HOST || '127.0.0.1';

app.use(cors());
app.use(express.json({ limit: '256kb' }));

app.use('/vendor', express.static(path.join(__dirname, 'node_modules/@smartledger/bsv'), {
  maxAge: '1h',
  immutable: false,
}));

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '5m',
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  },
}));

app.get('/healthz', (_req, res) => res.json({ ok: true }));

app.listen(PORT, HOST, () => {
  console.log(`web3keys listening on http://${HOST}:${PORT}`);
});
