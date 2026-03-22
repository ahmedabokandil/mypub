# YouTube Summarizer

A web application that summarizes YouTube videos using AI. Paste a YouTube URL, choose a summary type, and get an instant AI-generated summary.

## Features

- **Brief Summary** - 3-5 sentence overview
- **Detailed Summary** - Organized breakdown with bullet points
- **Key Points** - Numbered list of important takeaways
- Embedded video preview
- Dark themed responsive UI

## Setup

1. **Install dependencies:**
   ```bash
   cd youtube-summarizer
   pip install -r requirements.txt
   ```

2. **Configure API key:**
   ```bash
   cp .env.example .env
   # Edit .env and add your Anthropic API key
   ```

3. **Run the app:**
   ```bash
   python app.py
   ```

4. Open http://localhost:5000 in your browser.

## Requirements

- Python 3.10+
- An [Anthropic API key](https://console.anthropic.com/)
- The YouTube video must have captions/subtitles enabled
