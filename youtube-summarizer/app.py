import os
import re

import anthropic
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from youtube_transcript_api import YouTubeTranscriptApi

load_dotenv()

app = Flask(__name__)

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


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


def summarize_text(transcript: str, summary_type: str = "brief") -> str:
    """Use Claude to summarize the transcript."""
    prompts = {
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

    prompt = prompts.get(summary_type, prompts["brief"])

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": f"{prompt}\n\nTranscript:\n{transcript[:50000]}",
            }
        ],
    )
    return message.content[0].text


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/summarize", methods=["POST"])
def summarize():
    data = request.get_json()
    url = data.get("url", "").strip()
    summary_type = data.get("summary_type", "brief")

    if not url:
        return jsonify({"error": "Please provide a YouTube URL."}), 400

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
        summary = summarize_text(transcript, summary_type)
    except anthropic.AuthenticationError:
        return jsonify({"error": "Invalid API key. Check your ANTHROPIC_API_KEY."}), 401
    except anthropic.APIError as e:
        return jsonify({"error": f"API error: {e.message}"}), 500

    return jsonify({
        "summary": summary,
        "video_id": video_id,
        "transcript_length": len(transcript),
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
