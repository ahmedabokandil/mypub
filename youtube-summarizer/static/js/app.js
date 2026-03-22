const form = document.getElementById("summarize-form");
const urlInput = document.getElementById("url-input");
const submitBtn = document.getElementById("submit-btn");
const providerSelect = document.getElementById("provider-select");
const loading = document.getElementById("loading");
const errorDiv = document.getElementById("error");
const errorMessage = document.getElementById("error-message");
const result = document.getElementById("result");
const summaryContent = document.getElementById("summary-content");
const transcriptLength = document.getElementById("transcript-length");
const transcriptSource = document.getElementById("transcript-source");
const providerBadge = document.getElementById("provider-badge");
const loadingMessage = document.getElementById("loading-message");
const videoPreview = document.getElementById("video-preview");
const videoFrame = document.getElementById("video-frame");

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
        // Select first configured provider
        const first = providers.find((p) => p.configured);
        if (first) providerSelect.value = first.id;
    } catch {
        providerSelect.innerHTML = '<option value="claude">Claude (Anthropic)</option>';
    }
}

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

function showVideoPreview(videoId) {
    videoFrame.src = `https://www.youtube.com/embed/${videoId}`;
    videoPreview.classList.remove("hidden");
}

function hideAll() {
    loading.classList.add("hidden");
    errorDiv.classList.add("hidden");
    result.classList.add("hidden");
}

form.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideAll();

    const url = urlInput.value.trim();
    const summaryType = document.querySelector('input[name="summary_type"]:checked').value;
    const provider = providerSelect.value;

    if (!url) return;

    const videoId = extractVideoId(url);
    if (videoId) {
        showVideoPreview(videoId);
    }

    loading.classList.remove("hidden");
    loadingMessage.textContent = "Fetching transcript and generating summary...";
    submitBtn.disabled = true;
    submitBtn.textContent = "Summarizing...";

    // Update loading message after a delay (Whisper fallback takes longer)
    const loadingTimer = setTimeout(() => {
        loadingMessage.textContent = "No captions found. Downloading audio and transcribing with Whisper (this may take a while)...";
    }, 8000);

    try {
        const response = await fetch("/summarize", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, summary_type: summaryType, provider }),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Something went wrong.");
        }

        summaryContent.textContent = data.summary;
        transcriptLength.textContent = `Transcript: ${data.transcript_length.toLocaleString()} characters`;
        const sourceLabel = data.transcript_source === "whisper" ? "Whisper (audio)" : "YouTube captions";
        transcriptSource.textContent = ` | Source: ${sourceLabel}`;
        providerBadge.textContent = data.provider;
        result.classList.remove("hidden");
    } catch (err) {
        errorMessage.textContent = err.message;
        errorDiv.classList.remove("hidden");
    } finally {
        clearTimeout(loadingTimer);
        loading.classList.add("hidden");
        submitBtn.disabled = false;
        submitBtn.textContent = "Summarize";
    }
});

loadProviders();
