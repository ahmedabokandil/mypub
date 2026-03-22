const form = document.getElementById("summarize-form");
const urlInput = document.getElementById("url-input");
const submitBtn = document.getElementById("submit-btn");
const loading = document.getElementById("loading");
const errorDiv = document.getElementById("error");
const errorMessage = document.getElementById("error-message");
const result = document.getElementById("result");
const summaryContent = document.getElementById("summary-content");
const transcriptLength = document.getElementById("transcript-length");
const videoPreview = document.getElementById("video-preview");
const videoFrame = document.getElementById("video-frame");

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

    if (!url) return;

    const videoId = extractVideoId(url);
    if (videoId) {
        showVideoPreview(videoId);
    }

    loading.classList.remove("hidden");
    submitBtn.disabled = true;
    submitBtn.textContent = "Summarizing...";

    try {
        const response = await fetch("/summarize", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, summary_type: summaryType }),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Something went wrong.");
        }

        summaryContent.textContent = data.summary;
        transcriptLength.textContent = `Transcript: ${data.transcript_length.toLocaleString()} characters`;
        result.classList.remove("hidden");
    } catch (err) {
        errorMessage.textContent = err.message;
        errorDiv.classList.remove("hidden");
    } finally {
        loading.classList.add("hidden");
        submitBtn.disabled = false;
        submitBtn.textContent = "Summarize";
    }
});
