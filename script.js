const analyzeBtn = document.getElementById("analyzeBtn");
const resultSection = document.getElementById("resultSection");

const prediction = document.getElementById("prediction");
const confidence = document.getElementById("confidence");
const progressBar = document.getElementById("progressBar");

const suspiciousCount = document.getElementById("suspiciousCount");
const linkCount = document.getElementById("linkCount");

const warning = document.getElementById("warning");
const details = document.getElementById("details");

const clearBtn = document.getElementById("clearBtn");
const clearHistory = document.getElementById("clearHistory");
const historyList = document.getElementById("historyList");

const languageBtn = document.getElementById("languageBtn");


// -----------------------------
// Analyze Email
// -----------------------------

analyzeBtn.addEventListener("click", async () => {

    const sender = document.getElementById("sender").value.trim();
    const subject = document.getElementById("subject").value.trim();
    const body = document.getElementById("body").value.trim();

    if (!subject && !body) {
        alert("Please enter an email subject or body.");
        return;
    }

    analyzeBtn.disabled = true;
    analyzeBtn.innerText = "⏳ Analyzing...";

    try {

        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                sender: sender,
                subject: subject,
                body: body
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed.");
        }

        showResult(data);
        saveHistory(data, subject);

    } catch (error) {

        alert(error.message);

    } finally {

        analyzeBtn.disabled = false;
        analyzeBtn.innerText = "🔍 Analyze Email";
    }
});


// -----------------------------
// Show Result
// -----------------------------

function showResult(data) {

    resultSection.classList.remove("hidden");

    prediction.innerText = data.prediction;

    confidence.innerText = data.confidence + "%";

    progressBar.style.width = data.confidence + "%";

    suspiciousCount.innerText =
        data.suspicious_words.length;

    linkCount.innerText =
        data.links.length;

    warning.innerText =
        data.warning;

    details.innerHTML = `
        <p><strong>Sender:</strong> ${escapeHTML(data.sender || "Not provided")}</p>

        <p><strong>Threat Level:</strong>
        ${escapeHTML(data.threat_level)}</p>

        <p><strong>Suspicious Words:</strong>
        ${data.suspicious_words.length
            ? data.suspicious_words.map(escapeHTML).join(", ")
            : "None detected"}
        </p>

        <p><strong>Detected Links:</strong>
        ${data.links.length
            ? data.links.map(escapeHTML).join("<br>")
            : "No links detected"}
        </p>

        <p><strong>Analysis:</strong>
        ${escapeHTML(data.reason)}</p>
    `;

    resultSection.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


// -----------------------------
// History
// -----------------------------

function saveHistory(data, subject) {

    let history =
        JSON.parse(localStorage.getItem("mailguardHistory")) || [];

    const item = {
        subject: subject || "No subject",
        prediction: data.prediction,
        confidence: data.confidence,
        time: new Date().toLocaleString()
    };

    history.unshift(item);

    history = history.slice(0, 10);

    localStorage.setItem(
        "mailguardHistory",
        JSON.stringify(history)
    );

    renderHistory();
}


function renderHistory() {

    const history =
        JSON.parse(localStorage.getItem("mailguardHistory")) || [];

    if (!history.length) {

        historyList.innerHTML =
            `<p class="empty-history">No email analysis yet.</p>`;

        return;
    }

    historyList.innerHTML = history.map(item => {

        return `
            <div class="history-item">
                <div>
                    <strong>${escapeHTML(item.subject)}</strong>
                    <br>
                    <small>${escapeHTML(item.time)}</small>
                </div>

                <div>
                    <strong>${escapeHTML(item.prediction)}</strong>
                    <br>
                    <small>${item.confidence}%</small>
                </div>
            </div>
        `;

    }).join("");
}


clearHistory.addEventListener("click", () => {

    localStorage.removeItem("mailguardHistory");

    renderHistory();
});


// -----------------------------
// Clear Current Result
// -----------------------------

clearBtn.addEventListener("click", () => {

    resultSection.classList.add("hidden");

    document.getElementById("sender").value = "";
    document.getElementById("subject").value = "";
    document.getElementById("body").value = "";
});


// -----------------------------
// Tamil / English
// -----------------------------

let tamil = false;

languageBtn.addEventListener("click", () => {

    tamil = !tamil;

    if (tamil) {

        document.getElementById("title").innerText =
            "போலி மற்றும் சந்தேகமான Email-களை கண்டறியுங்கள்";

        document.getElementById("subtitle").innerText =
            "Email உள்ளடக்கம், links மற்றும் suspicious patterns-ஐ AI உதவியுடன் பகுப்பாய்வு செய்யுங்கள்.";

        languageBtn.innerText = "English";

    } else {

        document.getElementById("title").innerText =
            "Detect Fake & Suspicious Emails";

        document.getElementById("subtitle").innerText =
            "Analyze email content, links and suspicious patterns with AI-assisted security analysis.";

        languageBtn.innerText = "தமிழ்";
    }
});


// -----------------------------
// Security helper
// -----------------------------

function escapeHTML(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


// Load history when page opens
renderHistory();
