import glob
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import tempfile
import threading

import anthropic
import whisper
import yt_dlp
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from google import genai
from mistralai import Mistral
from openai import OpenAI
from youtube_transcript_api import YouTubeTranscriptApi

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(32).hex())
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database (SQLite cache)
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS cache (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.commit()
    return conn


def cache_get(key: str) -> dict | None:
    conn = get_db()
    try:
        row = conn.execute("SELECT value FROM cache WHERE key = ?", (key,)).fetchone()
        if row:
            return json.loads(row["value"])
        return None
    finally:
        conn.close()


def cache_set(key: str, value: dict):
    conn = get_db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO cache (key, value) VALUES (?, ?)",
            (key, json.dumps(value)),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
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
    "timestamps": (
        "Summarize this YouTube video transcript with timestamps. "
        "For each major topic or section, provide the approximate timestamp "
        "in [MM:SS] format and a brief description. Format as a list like:\n"
        "[00:00] Introduction - ...\n[02:15] Topic 1 - ...\n"
        "Use the timestamps provided in the transcript to determine timing."
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

# ---------------------------------------------------------------------------
# Whisper
# ---------------------------------------------------------------------------
_whisper_model = None
_whisper_lock = threading.Lock()

# Progress tracking for Whisper downloads
_progress_store: dict[str, dict] = {}


def get_whisper_model():
    global _whisper_model
    if _whisper_model is None:
        with _whisper_lock:
            if _whisper_model is None:
                model_size = os.getenv("WHISPER_MODEL", "base")
                logger.info("Loading Whisper model: %s", model_size)
                _whisper_model = whisper.load_model(model_size)
    return _whisper_model


# ---------------------------------------------------------------------------
# Video & transcript helpers
# ---------------------------------------------------------------------------
def extract_video_id(url: str) -> str | None:
    patterns = [
        r"(?:v=|/v/|youtu\.be/|/embed/)([a-zA-Z0-9_-]{11})",
        r"^([a-zA-Z0-9_-]{11})$",
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None


def extract_playlist_id(url: str) -> str | None:
    match = re.search(r"list=([a-zA-Z0-9_-]+)", url)
    return match.group(1) if match else None


def get_playlist_videos(playlist_url: str) -> list[dict]:
    ydl_opts = {
        "quiet": True,
        "no_warnings": True,
        "extract_flat": True,
        "skip_download": True,
    }
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(playlist_url, download=False)
        entries = info.get("entries", [])
        return [
            {"video_id": e["id"], "title": e.get("title", "Untitled")}
            for e in entries
            if e and e.get("id")
        ]


def get_transcript(video_id: str, language: str = "en") -> tuple[str, str, str | None]:
    """Fetch transcript with language preference.

    Returns (text, source, raw_with_timestamps_or_None).
    """
    # Try YouTube captions first
    try:
        ytt_api = YouTubeTranscriptApi()
        transcript = ytt_api.fetch(video_id, languages=[language, "en"])
        text = " ".join(snippet.text for snippet in transcript)
        # Build timestamped version for timestamp summaries
        ts_text = "\n".join(
            f"[{_format_seconds(snippet.start)}] {snippet.text}"
            for snippet in transcript
        )
        if text.strip():
            return text, "captions", ts_text
    except Exception:
        logger.info("No captions for %s (lang=%s), falling back to Whisper", video_id, language)

    text = transcribe_with_whisper(video_id, language)
    return text, "whisper", None


def _format_seconds(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def transcribe_with_whisper(video_id: str, language: str = "en") -> str:
    video_url = f"https://www.youtube.com/watch?v={video_id}"
    tmp_dir = tempfile.mkdtemp(prefix="yt_whisper_")

    _progress_store[video_id] = {"stage": "downloading", "percent": 0}

    def progress_hook(d):
        if d.get("status") == "downloading":
            total = d.get("total_bytes") or d.get("total_bytes_estimate") or 0
            downloaded = d.get("downloaded_bytes", 0)
            if total > 0:
                _progress_store[video_id] = {
                    "stage": "downloading",
                    "percent": int(downloaded / total * 100),
                }
        elif d.get("status") == "finished":
            _progress_store[video_id] = {"stage": "transcribing", "percent": 100}

    try:
        ydl_opts = {
            "format": "bestaudio/best",
            "outtmpl": os.path.join(tmp_dir, "audio.%(ext)s"),
            "postprocessors": [
                {
                    "key": "FFmpegExtractAudio",
                    "preferredcodec": "mp3",
                    "preferredquality": "64",
                }
            ],
            "quiet": True,
            "no_warnings": True,
            "progress_hooks": [progress_hook],
        }

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([video_url])

        audio_files = glob.glob(os.path.join(tmp_dir, "audio.*"))
        if not audio_files:
            raise RuntimeError("Audio download failed.")
        audio_path = audio_files[0]

        _progress_store[video_id] = {"stage": "transcribing", "percent": 0}
        model = get_whisper_model()
        result = model.transcribe(audio_path, language=language if language != "auto" else None)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        _progress_store.pop(video_id, None)

    return result["text"]


# ---------------------------------------------------------------------------
# Prompt building & chunking
# ---------------------------------------------------------------------------
MAX_TRANSCRIPT_CHARS = 50000
CHUNK_SIZE = 40000
CHUNK_OVERLAP = 2000


def build_prompt(transcript: str, summary_type: str, custom_prompt: str | None = None) -> str:
    if custom_prompt:
        prompt = custom_prompt
    else:
        prompt = SUMMARY_PROMPTS.get(summary_type, SUMMARY_PROMPTS["brief"])
    return f"{prompt}\n\nTranscript:\n{transcript[:MAX_TRANSCRIPT_CHARS]}"


def chunk_transcript(text: str) -> list[str]:
    if len(text) <= MAX_TRANSCRIPT_CHARS:
        return [text]
    chunks = []
    start = 0
    while start < len(text):
        end = start + CHUNK_SIZE
        chunks.append(text[start:end])
        start = end - CHUNK_OVERLAP
    return chunks


def build_merge_prompt(chunk_summaries: list[str], summary_type: str, custom_prompt: str | None = None) -> str:
    combined = "\n\n---\n\n".join(
        f"Part {i+1}:\n{s}" for i, s in enumerate(chunk_summaries)
    )
    base = custom_prompt or SUMMARY_PROMPTS.get(summary_type, SUMMARY_PROMPTS["brief"])
    return (
        f"The following are summaries of consecutive parts of a long video transcript. "
        f"Please merge them into a single coherent summary.\n\n"
        f"Instructions: {base}\n\nPart summaries:\n{combined}"
    )


# ---------------------------------------------------------------------------
# Summarizer functions
# ---------------------------------------------------------------------------
def summarize_with_claude(prompt: str) -> str:
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def stream_with_claude(prompt: str):
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    with client.messages.stream(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        for text in stream.text_stream:
            yield text


def summarize_with_mistral(prompt: str) -> str:
    client = Mistral(api_key=os.getenv("MISTRAL_API_KEY"))
    response = client.chat.complete(
        model="mistral-large-latest",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1024,
    )
    return response.choices[0].message.content


def stream_with_mistral(prompt: str):
    client = Mistral(api_key=os.getenv("MISTRAL_API_KEY"))
    response = client.chat.stream(
        model="mistral-large-latest",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1024,
    )
    for event in response:
        chunk = event.data.choices[0].delta.content
        if chunk:
            yield chunk


def summarize_with_gemini(prompt: str) -> str:
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt,
    )
    return response.text


def stream_with_gemini(prompt: str):
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
    for chunk in client.models.generate_content_stream(
        model="gemini-2.0-flash",
        contents=prompt,
    ):
        if chunk.text:
            yield chunk.text


def summarize_with_ollama(prompt: str) -> str:
    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "llama3")
    client = OpenAI(base_url=f"{ollama_host}/v1", api_key="ollama")
    response = client.chat.completions.create(
        model=ollama_model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1024,
    )
    return response.choices[0].message.content


def stream_with_ollama(prompt: str):
    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "llama3")
    client = OpenAI(base_url=f"{ollama_host}/v1", api_key="ollama")
    response = client.chat.completions.create(
        model=ollama_model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1024,
        stream=True,
    )
    for chunk in response:
        delta = chunk.choices[0].delta.content
        if delta:
            yield delta


SUMMARIZERS = {
    "claude": summarize_with_claude,
    "mistral": summarize_with_mistral,
    "gemini": summarize_with_gemini,
    "ollama": summarize_with_ollama,
}

STREAMERS = {
    "claude": stream_with_claude,
    "mistral": stream_with_mistral,
    "gemini": stream_with_gemini,
    "ollama": stream_with_ollama,
}


def do_qa(provider: str, transcript: str, question: str) -> str:
    prompt = (
        f"Based on the following video transcript, answer this question:\n\n"
        f"Question: {question}\n\nTranscript:\n{transcript[:MAX_TRANSCRIPT_CHARS]}"
    )
    return SUMMARIZERS[provider](prompt)


def do_summarize(provider: str, transcript: str, summary_type: str,
                 custom_prompt: str | None = None) -> str:
    """Summarize with automatic chunking for long transcripts."""
    chunks = chunk_transcript(transcript)
    if len(chunks) == 1:
        prompt = build_prompt(transcript, summary_type, custom_prompt)
        return SUMMARIZERS[provider](prompt)

    # Summarize each chunk, then merge
    chunk_summaries = []
    for chunk in chunks:
        prompt = build_prompt(chunk, summary_type, custom_prompt)
        chunk_summaries.append(SUMMARIZERS[provider](prompt))

    merge_prompt = build_merge_prompt(chunk_summaries, summary_type, custom_prompt)
    return SUMMARIZERS[provider](merge_prompt)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/providers")
def providers():
    available = []
    for key, info in PROVIDERS.items():
        configured = info["env_key"] is None or bool(os.getenv(info["env_key"]))
        available.append({
            "id": key,
            "name": info["name"],
            "configured": configured,
        })
    return jsonify(available)


@app.route("/progress/<video_id>")
def progress(video_id):
    return jsonify(_progress_store.get(video_id, {"stage": "waiting", "percent": 0}))


@app.route("/summarize", methods=["POST"])
def summarize():
    data = request.get_json()
    url = data.get("url", "").strip()
    summary_type = data.get("summary_type", "brief")
    provider = data.get("provider", "claude")
    language = data.get("language", "en")
    custom_prompt = data.get("custom_prompt", "").strip() or None
    use_stream = data.get("stream", False)

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

    # Check cache
    cache_key = hashlib.sha256(
        f"{video_id}:{summary_type}:{provider}:{language}:{custom_prompt or ''}".encode()
    ).hexdigest()

    cached = cache_get(cache_key)
    if cached:
        cached["from_cache"] = True
        return jsonify(cached)

    try:
        transcript, transcript_source, ts_transcript = get_transcript(video_id, language)
    except Exception as e:
        return jsonify({"error": f"Could not get transcript: {e}"}), 400

    if not transcript:
        return jsonify({"error": "Transcript is empty."}), 400

    # For timestamp summaries, prefer the timestamped transcript
    effective_transcript = ts_transcript if summary_type == "timestamps" and ts_transcript else transcript

    if use_stream and len(chunk_transcript(effective_transcript)) == 1:
        prompt = build_prompt(effective_transcript, summary_type, custom_prompt)

        def generate():
            full_text = []
            try:
                for token in STREAMERS[provider](prompt):
                    full_text.append(token)
                    yield f"data: {json.dumps({'token': token})}\n\n"
                # Send final metadata
                final_meta = {
                    "video_id": video_id,
                    "transcript_length": len(transcript),
                    "transcript_source": transcript_source,
                    "provider": PROVIDERS[provider]["name"],
                    "transcript": transcript,
                }
                # Cache the result (without 'done' flag)
                cache_set(cache_key, {
                    "summary": "".join(full_text),
                    **final_meta,
                })
                yield f"data: {json.dumps({'done': True, **final_meta})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    try:
        summary = do_summarize(provider, effective_transcript, summary_type, custom_prompt)
    except Exception as e:
        return jsonify({"error": f"{PROVIDERS[provider]['name']} error: {e}"}), 500

    result_data = {
        "summary": summary,
        "video_id": video_id,
        "transcript_length": len(transcript),
        "transcript_source": transcript_source,
        "provider": PROVIDERS[provider]["name"],
        "transcript": transcript,
    }

    cache_set(cache_key, result_data)

    return jsonify(result_data)


@app.route("/qa", methods=["POST"])
def qa():
    data = request.get_json()
    provider = data.get("provider", "claude")
    transcript = data.get("transcript", "").strip()[:MAX_TRANSCRIPT_CHARS]
    question = data.get("question", "").strip()[:500]

    if not transcript or not question:
        return jsonify({"error": "Transcript and question are required."}), 400

    if provider not in SUMMARIZERS:
        return jsonify({"error": f"Unknown provider: {provider}"}), 400

    provider_info = PROVIDERS[provider]
    if provider_info["env_key"] and not os.getenv(provider_info["env_key"]):
        return jsonify({"error": f"{provider_info['name']} API key not configured."}), 400

    try:
        answer = do_qa(provider, transcript, question)
    except Exception as e:
        return jsonify({"error": f"Q&A error: {e}"}), 500

    return jsonify({"answer": answer})


@app.route("/playlist", methods=["POST"])
def playlist():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url or not extract_playlist_id(url):
        return jsonify({"error": "Invalid playlist URL."}), 400

    try:
        videos = get_playlist_videos(url)
    except Exception as e:
        return jsonify({"error": f"Could not fetch playlist: {e}"}), 400

    return jsonify({"videos": videos})


@app.route("/compare", methods=["POST"])
def compare():
    data = request.get_json()
    url = data.get("url", "").strip()
    summary_type = data.get("summary_type", "brief")
    providers_list = data.get("providers", [])
    language = data.get("language", "en")
    custom_prompt = data.get("custom_prompt", "").strip() or None

    if not url:
        return jsonify({"error": "Please provide a YouTube URL."}), 400

    video_id = extract_video_id(url)
    if not video_id:
        return jsonify({"error": "Invalid YouTube URL."}), 400

    try:
        transcript, transcript_source, ts_transcript = get_transcript(video_id, language)
    except Exception as e:
        return jsonify({"error": f"Could not get transcript: {e}"}), 400

    if not transcript:
        return jsonify({"error": "Transcript is empty."}), 400

    effective_transcript = ts_transcript if summary_type == "timestamps" and ts_transcript else transcript

    results = {}
    for prov in providers_list:
        if prov not in SUMMARIZERS:
            results[prov] = {"error": f"Unknown provider: {prov}"}
            continue
        pinfo = PROVIDERS[prov]
        if pinfo["env_key"] and not os.getenv(pinfo["env_key"]):
            results[prov] = {"error": f"{pinfo['name']} not configured."}
            continue
        try:
            summary = do_summarize(prov, effective_transcript, summary_type, custom_prompt)
            results[prov] = {"summary": summary, "name": pinfo["name"]}
        except Exception as e:
            results[prov] = {"error": str(e)}

    return jsonify({
        "results": results,
        "video_id": video_id,
        "transcript_length": len(transcript),
        "transcript_source": transcript_source,
        "transcript": transcript,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
