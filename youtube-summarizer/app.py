import os
import re

import anthropic
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from google import genai
from mistralai import Mistral
from openai import OpenAI
from youtube_transcript_api import YouTubeTranscriptApi

load_dotenv()

app = Flask(__name__)

SUMMARY_PROMPTS = {
    "brief": (
        "Provide a concise summary (3-5 sentences) of this YouTube video transcript. "
        "Focus on the main topic and key takeaway."
    ),
    "detailed": (
        "Provide a detailed summary of this YouTube video transcript. "
        "Include all major points, arguments, and conclusions. "
        "Use bullet points for key topics and organize by theme."
    ),
    "key_points": (
        "Extract the key points from this YouTube video transcript. "
        "List them as numbered bullet points. Include only the most "
        "important facts, insights, and takeaways."
    ),
}

PROVIDERS = {
    "claude": {
        "name": "Claude (Anthropic)",
        "env_key": "ANTHROPIC_API_KEY",
    },
    "mistral": {
        "name": "Mistral AI",
        "env_key": "MISTRAL_API_KEY",
    },
    "gemini": {
        "name": "Google Gemini",
        "env_key": "GOOGLE_API_KEY",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "env_key": None,
    },
}


def extract_video_id(url: str) -> str | None:
    """Extract the YouTube video ID from various URL formats."""
    patterns = [
        r"(?:v=|/v/|youtu\.be/|/embed/)([a-zA-Z0-9_-]{11})",
        r"^([a-zA-Z0-9_-]{11})$",
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None


def get_transcript(video_id: str) -> str:
    """Fetch the transcript for a YouTube video."""
    ytt_api = YouTubeTranscriptApi()
    transcript = ytt_api.fetch(video_id)
    return " ".join(snippet.text for snippet in transcript)


def build_prompt(transcript: str, summary_type: str) -> str:
    prompt = SUMMARY_PROMPTS.get(summary_type, SUMMARY_PROMPTS["brief"])
    return f"{prompt}\n\nTranscript:\n{transcript[:50000]}"


def summarize_with_claude(transcript: str, summary_type: str) -> str:
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": build_prompt(transcript, summary_type)}],
    )
    return message.content[0].text


def summarize_with_mistral(transcript: str, summary_type: str) -> str:
    client = Mistral(api_key=os.getenv("MISTRAL_API_KEY"))
    response = client.chat.complete(
        model="mistral-large-latest",
        messages=[{"role": "user", "content": build_prompt(transcript, summary_type)}],
        max_tokens=1024,
    )
    return response.choices[0].message.content


def summarize_with_gemini(transcript: str, summary_type: str) -> str:
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=build_prompt(transcript, summary_type),
    )
    return response.text


def summarize_with_ollama(transcript: str, summary_type: str) -> str:
    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "llama3")
    client = OpenAI(base_url=f"{ollama_host}/v1", api_key="ollama")
    response = client.chat.completions.create(
        model=ollama_model,
        messages=[{"role": "user", "content": build_prompt(transcript, summary_type)}],
        max_tokens=1024,
    )
    return response.choices[0].message.content


SUMMARIZERS = {
    "claude": summarize_with_claude,
    "mistral": summarize_with_mistral,
    "gemini": summarize_with_gemini,
    "ollama": summarize_with_ollama,
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/providers")
def providers():
    """Return available providers based on configured API keys."""
    available = []
    for key, info in PROVIDERS.items():
        configured = info["env_key"] is None or bool(os.getenv(info["env_key"]))
        available.append({
            "id": key,
            "name": info["name"],
            "configured": configured,
        })
    return jsonify(available)


@app.route("/summarize", methods=["POST"])
def summarize():
    data = request.get_json()
    url = data.get("url", "").strip()
    summary_type = data.get("summary_type", "brief")
    provider = data.get("provider", "claude")

    if not url:
        return jsonify({"error": "Please provide a YouTube URL."}), 400

    if provider not in SUMMARIZERS:
        return jsonify({"error": f"Unknown provider: {provider}"}), 400

    provider_info = PROVIDERS[provider]
    if provider_info["env_key"] and not os.getenv(provider_info["env_key"]):
        return jsonify({"error": f"{provider_info['name']} API key not configured. Set {provider_info['env_key']} in .env"}), 400

    video_id = extract_video_id(url)
    if not video_id:
        return jsonify({"error": "Invalid YouTube URL."}), 400

    try:
        transcript = get_transcript(video_id)
    except Exception:
        return jsonify({"error": "Could not fetch transcript. Make sure the video has captions enabled."}), 400

    if not transcript:
        return jsonify({"error": "Transcript is empty."}), 400

    try:
        summary = SUMMARIZERS[provider](transcript, summary_type)
    except Exception as e:
        return jsonify({"error": f"{PROVIDERS[provider]['name']} error: {e}"}), 500

    return jsonify({
        "summary": summary,
        "video_id": video_id,
        "transcript_length": len(transcript),
        "provider": PROVIDERS[provider]["name"],
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
