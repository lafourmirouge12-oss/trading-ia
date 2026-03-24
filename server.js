require('dotenv').config({ path: __dirname + '/.env' });
const express = require('express');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const upload = multer({ dest: 'uploads/' });
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

app.use(express.static('public'));

app.post('/analyze', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Aucune image reçue' });
    }

    const imageData = fs.readFileSync(req.file.path);
    const base64Image = imageData.toString('base64');
    const mimeType = req.file.mimetype || 'image/png';

    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1024,
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'image',
              source: {
                type: 'base64',
                media_type: mimeType,
                data: base64Image
              }
            },
            {
              type: 'text',
              text: `Tu es un trader professionnel avec 15 ans d'expérience. Analyse ce graphique et réponds en français avec exactement ce format :

DÉCISION: BUY ou SELL — Confiance XX%

TENDANCE: [2-3 phrases max, direct et cash]

ENTRÉE: [prix précis ou zone ex: 4500 - 4520]

STOP LOSS: [prix précis ex: 4450]

TAKE PROFIT: [prix précis ex: 4650]

SETUP: [2-3 phrases sur les indicateurs, bref et concret]

IMPORTANT: Sois direct comme un vrai trader. Pas de blabla. Phrases courtes. Donne des chiffres précis.`
            }
          ]
        }
      ]
    });

    fs.unlinkSync(req.file.path);
    res.json({ result: response.content[0].text });

  } catch (err) {
    console.error('Erreur détaillée:', err.message);
    res.status(500).json({ error: 'Erreur : ' + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Serveur lancé sur http://localhost:${PORT}`);
});