// ---------------------------------------------------------------------------
// DOM elements
// ---------------------------------------------------------------------------
const form = document.getElementById("summarize-form");
const urlInput = document.getElementById("url-input");
const submitBtn = document.getElementById("submit-btn");
const providerSelect = document.getElementById("provider-select");
const languageSelect = document.getElementById("language-select");
const streamToggle = document.getElementById("stream-toggle");
const customPrompt = document.getElementById("custom-prompt");
const loading = document.getElementById("loading");
const loadingMessage = document.getElementById("loading-message");
const progressBarContainer = document.getElementById("progress-bar-container");
const progressBar = document.getElementById("progress-bar");
const progressLabel = document.getElementById("progress-label");
const errorDiv = document.getElementById("error");
const errorMessage = document.getElementById("error-message");
const resultDiv = document.getElementById("result");
const summaryContent = document.getElementById("summary-content");
const transcriptLength = document.getElementById("transcript-length");
const transcriptSource = document.getElementById("transcript-source");
const cacheIndicator = document.getElementById("cache-indicator");
const providerBadge = document.getElementById("provider-badge");
const videoPreview = document.getElementById("video-preview");
const videoFrame = document.getElementById("video-frame");
const copyBtn = document.getElementById("copy-btn");
const exportMdBtn = document.getElementById("export-md-btn");
const exportTxtBtn = document.getElementById("export-txt-btn");
const transcriptViewer = document.getElementById("transcript-viewer");
const transcriptText = document.getElementById("transcript-text");
const qaInput = document.getElementById("qa-input");
const qaBtn = document.getElementById("qa-btn");
const qaAnswer = document.getElementById("qa-answer");
const compareBtn = document.getElementById("compare-btn");
const comparePanel = document.getElementById("compare-panel");
const compareResults = document.getElementById("compare-results");
const playlistPanel = document.getElementById("playlist-panel");
const playlistList = document.getElementById("playlist-list");
const historyList = document.getElementById("history-list");
const clearHistoryBtn = document.getElementById("clear-history-btn");
const themeToggle = document.getElementById("theme-toggle");
const themeIcon = document.getElementById("theme-icon");

// State
let currentTranscript = "";
let currentVideoId = "";
let progressInterval = null;

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------
function initTheme() {
    const saved = localStorage.getItem("yt-summarizer-theme") || "dark";
    document.body.className = saved;
    themeIcon.textContent = saved === "dark" ? "\u2600" : "\u263E";
}

themeToggle.addEventListener("click", () => {
    const isDark = document.body.classList.contains("dark");
    const next = isDark ? "light" : "dark";
    document.body.className = next;
    localStorage.setItem("yt-summarizer-theme", next);
    themeIcon.textContent = next === "dark" ? "\u2600" : "\u263E";
});

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------
async function loadProviders() {
    try {
        const response = await fetch("/providers");
        const providers = await response.json();
        providerSelect.innerHTML = "";
        providers.forEach((p) => {
            const option = document.createElement("option");
            option.value = p.id;
            option.textContent = p.name + (p.configured ? "" : " (not configured)");
            option.disabled = !p.configured;
            providerSelect.appendChild(option);
        });
        const first = providers.find((p) => p.configured);
        if (first) providerSelect.value = first.id;
    } catch {
        providerSelect.innerHTML = '<option value="claude">Claude (Anthropic)</option>';
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function extractVideoId(url) {
    const patterns = [
        /(?:v=|\/v\/|youtu\.be\/|\/embed\/)([a-zA-Z0-9_-]{11})/,
        /^([a-zA-Z0-9_-]{11})$/,
    ];
    for (const pattern of patterns) {
        const match = url.match(pattern);
        if (match) return match[1];
    }
    return null;
}

function isPlaylistUrl(url) {
    return /list=/.test(url);
}

function showVideoPreview(videoId) {
    videoFrame.src = `https://www.youtube.com/embed/${videoId}`;
    videoPreview.classList.remove("hidden");
}

function hideAll() {
    loading.classList.add("hidden");
    errorDiv.classList.add("hidden");
    resultDiv.classList.add("hidden");
    comparePanel.classList.add("hidden");
    progressBarContainer.classList.add("hidden");
    stopProgressPolling();
}

function showError(msg) {
    errorMessage.textContent = msg;
    errorDiv.classList.remove("hidden");
}

function downloadFile(content, filename) {
    const blob = new Blob([content], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
}

// ---------------------------------------------------------------------------
// Progress polling (for Whisper)
// ---------------------------------------------------------------------------
function startProgressPolling(videoId) {
    progressBarContainer.classList.remove("hidden");
    progressInterval = setInterval(async () => {
        try {
            const resp = await fetch(`/progress/${videoId}`);
            const data = await resp.json();
            if (data.stage === "downloading") {
                progressBar.style.width = data.percent + "%";
                progressLabel.textContent = `Downloading audio: ${data.percent}%`;
            } else if (data.stage === "transcribing") {
                progressBar.style.width = "100%";
                progressLabel.textContent = "Transcribing with Whisper...";
            }
        } catch { /* ignore */ }
    }, 1000);
}

function stopProgressPolling() {
    if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
    }
}

// ---------------------------------------------------------------------------
// History (localStorage)
// ---------------------------------------------------------------------------
const HISTORY_KEY = "yt-summarizer-history";
const MAX_HISTORY = 20;

function getHistory() {
    try {
        return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    } catch {
        return [];
    }
}

function saveToHistory(entry) {
    const history = getHistory();
    // Avoid duplicates by video_id + provider + summary_type
    const idx = history.findIndex(
        (h) => h.video_id === entry.video_id && h.provider === entry.provider && h.summary_type === entry.summary_type
    );
    if (idx !== -1) history.splice(idx, 1);
    history.unshift(entry);
    if (history.length > MAX_HISTORY) history.pop();
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    renderHistory();
}

function renderHistory() {
    const history = getHistory();
    if (history.length === 0) {
        historyList.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem;">No history yet.</p>';
        return;
    }
    historyList.innerHTML = history
        .map(
            (h, i) => `
        <div class="history-item" data-index="${i}">
            <div>
                <div class="history-title">${h.video_id}</div>
                <div class="history-meta">${h.provider} &middot; ${h.summary_type} &middot; ${new Date(h.timestamp).toLocaleDateString()}</div>
            </div>
        </div>`
        )
        .join("");

    historyList.querySelectorAll(".history-item").forEach((el) => {
        el.addEventListener("click", () => {
            const idx = parseInt(el.dataset.index);
            const entry = history[idx];
            displayResult(entry);
            showVideoPreview(entry.video_id);
            currentVideoId = entry.video_id;
            currentTranscript = entry.transcript || "";
        });
    });
}

clearHistoryBtn.addEventListener("click", () => {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
});

// ---------------------------------------------------------------------------
// Display result
// ---------------------------------------------------------------------------
function displayResult(data) {
    summaryContent.textContent = data.summary;
    transcriptLength.textContent = `Transcript: ${(data.transcript_length || 0).toLocaleString()} characters`;
    const sourceLabel = data.transcript_source === "whisper" ? "Whisper (audio)" : "YouTube captions";
    transcriptSource.textContent = ` | Source: ${sourceLabel}`;
    cacheIndicator.textContent = data.from_cache ? " | (cached)" : "";
    providerBadge.textContent = data.provider;
    currentTranscript = data.transcript || "";
    currentVideoId = data.video_id || "";
    transcriptText.textContent = currentTranscript;
    qaAnswer.classList.add("hidden");
    resultDiv.classList.remove("hidden");
}

// ---------------------------------------------------------------------------
// Playlist
// ---------------------------------------------------------------------------
async function handlePlaylist(url) {
    loading.classList.remove("hidden");
    loadingMessage.textContent = "Loading playlist...";
    submitBtn.disabled = true;

    try {
        const resp = await fetch("/playlist", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error);

        playlistList.innerHTML = data.videos
            .map(
                (v) =>
                    `<div class="playlist-item" data-id="${v.video_id}">${v.title}</div>`
            )
            .join("");

        playlistList.querySelectorAll(".playlist-item").forEach((el) => {
            el.addEventListener("click", () => {
                urlInput.value = `https://www.youtube.com/watch?v=${el.dataset.id}`;
                playlistPanel.classList.add("hidden");
                form.dispatchEvent(new Event("submit"));
            });
        });

        playlistPanel.classList.remove("hidden");
    } catch (err) {
        showError(err.message);
    } finally {
        loading.classList.add("hidden");
        submitBtn.disabled = false;
    }
}

// ---------------------------------------------------------------------------
// Main form submission
// ---------------------------------------------------------------------------
form.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideAll();

    const url = urlInput.value.trim();
    const summaryType = document.querySelector('input[name="summary_type"]:checked').value;
    const provider = providerSelect.value;
    const language = languageSelect.value;
    const custom = customPrompt.value.trim();
    const useStream = streamToggle.checked;

    if (!url) return;

    // Check if playlist
    if (isPlaylistUrl(url) && !extractVideoId(url)) {
        return handlePlaylist(url);
    }

    const videoId = extractVideoId(url);
    if (videoId) {
        showVideoPreview(videoId);
        currentVideoId = videoId;
    }

    loading.classList.remove("hidden");
    loadingMessage.textContent = "Fetching transcript and generating summary...";
    submitBtn.disabled = true;
    submitBtn.textContent = "Summarizing...";

    const loadingTimer = setTimeout(() => {
        loadingMessage.textContent = "No captions found. Downloading audio and transcribing with Whisper...";
        if (videoId) startProgressPolling(videoId);
    }, 8000);

    try {
        if (useStream) {
            await handleStreamResponse(url, summaryType, provider, language, custom);
        } else {
            await handleNormalResponse(url, summaryType, provider, language, custom);
        }
    } catch (err) {
        showError(err.message);
    } finally {
        clearTimeout(loadingTimer);
        stopProgressPolling();
        loading.classList.add("hidden");
        submitBtn.disabled = false;
        submitBtn.textContent = "Summarize";
    }
});

async function handleNormalResponse(url, summaryType, provider, language, custom) {
    const response = await fetch("/summarize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            url,
            summary_type: summaryType,
            provider,
            language,
            custom_prompt: custom,
            stream: false,
        }),
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Something went wrong.");

    displayResult(data);
    saveToHistory({
        video_id: data.video_id,
        summary: data.summary,
        provider: data.provider,
        summary_type: summaryType,
        transcript_length: data.transcript_length,
        transcript_source: data.transcript_source,
        transcript: data.transcript,
        from_cache: data.from_cache,
        timestamp: Date.now(),
    });
}

async function handleStreamResponse(url, summaryType, provider, language, custom) {
    const response = await fetch("/summarize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            url,
            summary_type: summaryType,
            provider,
            language,
            custom_prompt: custom,
            stream: true,
        }),
    });

    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Something went wrong.");
    }

    // Show result area immediately for streaming
    summaryContent.textContent = "";
    resultDiv.classList.remove("hidden");
    loading.classList.add("hidden");

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let fullText = "";

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();

        for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const jsonStr = line.slice(6);
            try {
                const data = JSON.parse(jsonStr);
                if (data.error) throw new Error(data.error);
                if (data.token) {
                    fullText += data.token;
                    summaryContent.textContent = fullText;
                }
                if (data.done) {
                    transcriptLength.textContent = `Transcript: ${(data.transcript_length || 0).toLocaleString()} characters`;
                    const sourceLabel = data.transcript_source === "whisper" ? "Whisper (audio)" : "YouTube captions";
                    transcriptSource.textContent = ` | Source: ${sourceLabel}`;
                    cacheIndicator.textContent = "";
                    providerBadge.textContent = data.provider;
                    currentTranscript = data.transcript || "";
                    currentVideoId = data.video_id || "";
                    transcriptText.textContent = currentTranscript;

                    saveToHistory({
                        video_id: data.video_id,
                        summary: fullText,
                        provider: data.provider,
                        summary_type: document.querySelector('input[name="summary_type"]:checked').value,
                        transcript_length: data.transcript_length,
                        transcript_source: data.transcript_source,
                        transcript: data.transcript,
                        timestamp: Date.now(),
                    });
                }
            } catch (parseErr) {
                if (parseErr.message !== "Unexpected end of JSON input") {
                    throw parseErr;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Export buttons
// ---------------------------------------------------------------------------
copyBtn.addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText(summaryContent.textContent);
        copyBtn.textContent = "Copied!";
        setTimeout(() => (copyBtn.textContent = "Copy"), 2000);
    } catch {
        copyBtn.textContent = "Failed";
        setTimeout(() => (copyBtn.textContent = "Copy"), 2000);
    }
});

exportMdBtn.addEventListener("click", () => {
    const md = `# YouTube Video Summary\n\n**Video:** https://www.youtube.com/watch?v=${currentVideoId}\n**Provider:** ${providerBadge.textContent}\n\n## Summary\n\n${summaryContent.textContent}\n`;
    downloadFile(md, `summary-${currentVideoId}.md`);
});

exportTxtBtn.addEventListener("click", () => {
    downloadFile(summaryContent.textContent, `summary-${currentVideoId}.txt`);
});

// ---------------------------------------------------------------------------
// Q&A
// ---------------------------------------------------------------------------
qaBtn.addEventListener("click", async () => {
    const question = qaInput.value.trim();
    if (!question || !currentTranscript) return;

    qaBtn.disabled = true;
    qaBtn.textContent = "Thinking...";
    qaAnswer.textContent = "";
    qaAnswer.classList.remove("hidden");

    try {
        const resp = await fetch("/qa", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                provider: providerSelect.value,
                transcript: currentTranscript,
                question,
            }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error);
        qaAnswer.textContent = data.answer;
    } catch (err) {
        qaAnswer.textContent = `Error: ${err.message}`;
    } finally {
        qaBtn.disabled = false;
        qaBtn.textContent = "Ask";
    }
});

qaInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        e.preventDefault();
        qaBtn.click();
    }
});

// ---------------------------------------------------------------------------
// Compare providers
// ---------------------------------------------------------------------------
compareBtn.addEventListener("click", async () => {
    const url = urlInput.value.trim();
    if (!url) {
        showError("Enter a YouTube URL first.");
        return;
    }

    const summaryType = document.querySelector('input[name="summary_type"]:checked').value;
    const language = languageSelect.value;
    const custom = customPrompt.value.trim();

    // Get all configured providers
    let providersList;
    try {
        const resp = await fetch("/providers");
        const all = await resp.json();
        providersList = all.filter((p) => p.configured).map((p) => p.id);
    } catch {
        showError("Could not load providers.");
        return;
    }

    if (providersList.length < 2) {
        showError("Need at least 2 configured providers to compare.");
        return;
    }

    hideAll();
    loading.classList.remove("hidden");
    loadingMessage.textContent = `Comparing ${providersList.length} providers...`;
    compareBtn.disabled = true;

    try {
        const resp = await fetch("/compare", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url,
                summary_type: summaryType,
                providers: providersList,
                language,
                custom_prompt: custom,
            }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error);

        const videoId = extractVideoId(url);
        if (videoId) showVideoPreview(videoId);

        compareResults.innerHTML = "";
        for (const [provId, result] of Object.entries(data.results)) {
            const card = document.createElement("div");
            card.className = "compare-card";
            if (result.error) {
                card.innerHTML = `<h3>${provId}</h3><div class="compare-error">${result.error}</div>`;
            } else {
                card.innerHTML = `<h3>${result.name}</h3><div class="compare-body">${result.summary}</div>`;
            }
            compareResults.appendChild(card);
        }

        currentTranscript = data.transcript || "";
        comparePanel.classList.remove("hidden");
    } catch (err) {
        showError(err.message);
    } finally {
        loading.classList.add("hidden");
        compareBtn.disabled = false;
    }
});

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
initTheme();
loadProviders();
renderHistory();
