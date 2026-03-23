# YouTube Summarizer

A web application that summarizes YouTube videos using AI. Paste a YouTube URL, choose your AI provider and summary type, and get an instant summary.

## Features

- **Multiple AI Providers** - Claude, Mistral, Google Gemini, and Ollama (local)
- **Brief Summary** - 3-5 sentence overview
- **Detailed Summary** - Organized breakdown with bullet points
- **Key Points** - Numbered list of important takeaways
- Embedded video preview
- Dark themed responsive UI
- Auto-detects which providers are configured

## Supported Providers

| Provider | Model | API Key Required |
|----------|-------|-----------------|
| Claude (Anthropic) | claude-sonnet-4-20250514 | Yes |
| Mistral AI | mistral-large-latest | Yes |
| Google Gemini | gemini-2.0-flash | Yes |
| Ollama (Local) | llama3 (configurable) | No |

## Setup

1. **Install dependencies:**
   ```bash
   cd youtube-summarizer
   pip install -r requirements.txt
   ```

2. **Configure API keys:**
   ```bash
   cp .env.example .env
   # Edit .env and add API keys for the providers you want to use
   ```

3. **For Ollama (optional):**
   ```bash
   # Install Ollama from https://ollama.com
   ollama pull llama3
   ```

4. **Run the app:**
   ```bash
   python app.py
   ```

5. Open http://localhost:5000 in your browser.

## Requirements

- Python 3.10+
- At least one AI provider configured (API key or Ollama running locally)
- The YouTube video must have captions/subtitles enabled
