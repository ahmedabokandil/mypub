const express = require('express');
const auth = require('../middleware/auth');

const router = express.Router();

// POST /api/link-preview - fetch OpenGraph data
router.post('/', auth, async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const ogs = require('open-graph-scraper');
    const { result, error } = await ogs({ url, timeout: 10000 });

    if (error) {
      return res.status(400).json({ error: 'Failed to fetch link preview' });
    }

    res.json({
      title: result.ogTitle || result.twitterTitle || null,
      description: result.ogDescription || result.twitterDescription || null,
      image: result.ogImage?.[0]?.url || result.twitterImage?.[0]?.url || null,
      url: result.ogUrl || url,
    });
  } catch (error) {
    console.error('Link preview error:', error);
    res.status(500).json({ error: 'Failed to fetch link preview' });
  }
});

module.exports = router;
