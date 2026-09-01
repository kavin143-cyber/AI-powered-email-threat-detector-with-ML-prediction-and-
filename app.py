from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import re
import os
import pickle
import requests

app = Flask(__name__)
CORS(app)

# =========================================================
# AI MAILGUARD - CONFIGURATION
# =========================================================

MODEL_PATH = "model.pkl"
VECTORIZER_PATH = "vectorizer.pkl"

# Google Safe Browsing API key
# IMPORTANT:
# Set this as an environment variable.
GOOGLE_SAFE_BROWSING_KEY = os.getenv(
    "GOOGLE_SAFE_BROWSING_KEY"
)

model = None
vectorizer = None


# =========================================================
# LOAD ML MODEL
# =========================================================

if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):

    try:

        with open(MODEL_PATH, "rb") as file:
            model = pickle.load(file)

        with open(VECTORIZER_PATH, "rb") as file:
            vectorizer = pickle.load(file)

        print("ML model loaded successfully.")

    except Exception as error:

        print("ML model loading error:", error)


# =========================================================
# SUSPICIOUS EMAIL PATTERNS
# =========================================================

SUSPICIOUS_WORDS = [
    "urgent",
    "verify",
    "verification",
    "account suspended",
    "account locked",
    "click here",
    "login",
    "password",
    "otp",
    "confirm",
    "security alert",
    "winner",
    "prize",
    "lottery",
    "free money",
    "refund",
    "payment",
    "credit card",
    "bank",
    "claim",
    "limited time",
    "act now"
]


URGENT_PATTERNS = [
    "immediately",
    "right now",
    "within 24 hours",
    "last chance",
    "action required",
    "respond immediately"
]


CREDENTIAL_PATTERNS = [
    "send your password",
    "share your password",
    "send otp",
    "share otp",
    "enter your password",
    "give me your password"
]


# =========================================================
# EXTRACT URLS
# =========================================================

def extract_urls(text):

    pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'

    return re.findall(
        pattern,
        text,
        re.IGNORECASE
    )


# =========================================================
# GOOGLE SAFE BROWSING
# =========================================================

def check_google_safe_browsing(urls):

    if not GOOGLE_SAFE_BROWSING_KEY:

        return {
            "checked": False,
            "threats": [],
            "message": "Google Safe Browsing API key not configured."
        }


    if not urls:

        return {
            "checked": False,
            "threats": [],
            "message": "No URLs found."
        }


    endpoint = (
        "https://safebrowsing.googleapis.com/"
        "v4/threatMatches:find"
    )


    payload = {

        "client": {
            "clientId": "ai-mailguard",
            "clientVersion": "1.0"
        },

        "threatInfo": {

            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],

            "platformTypes": [
                "ANY_PLATFORM"
            ],

            "threatEntryTypes": [
                "URL"
            ],

            "threatEntries": [
                {
                    "url": url
                }
                for url in urls
            ]
        }
    }


    try:

        response = requests.post(
            endpoint,
            params={
                "key": GOOGLE_SAFE_BROWSING_KEY
            },
            json=payload,
            timeout=8
        )

        response.raise_for_status()

        result = response.json()

        threats = result.get(
            "matches",
            []
        )


        return {

            "checked": True,

            "threats": threats,

            "message":
                "Google Safe Browsing check completed."

        }


    except requests.RequestException as error:

        print(
            "Google Safe Browsing error:",
            error
        )

        return {

            "checked": False,

            "threats": [],

            "message":
                "Google Safe Browsing service could not be reached."

        }


# =========================================================
# SUSPICIOUS WORD DETECTION
# =========================================================

def detect_suspicious_words(text):

    text = text.lower()

    found = []

    for word in SUSPICIOUS_WORDS:

        if word in text:

            found.append(word)


    return list(
        dict.fromkeys(found)
    )


# =========================================================
# SENDER DOMAIN
# =========================================================

def extract_email_domain(sender):

    if "@" not in sender:

        return ""

    return sender.split("@")[-1].lower().strip()


# =========================================================
# BASIC RISK ANALYSIS
# =========================================================

def calculate_risk(sender, subject, body):

    text = (
        f"{subject} {body}"
    ).lower()


    risk = 0

    reasons = []


    # -----------------------------------------
    # Suspicious words
    # -----------------------------------------

    suspicious_words = (
        detect_suspicious_words(text)
    )


    if suspicious_words:

        points = min(
            len(suspicious_words) * 5,
            35
        )

        risk += points

        reasons.append(
            f"{len(suspicious_words)} suspicious language pattern(s)"
        )


    # -----------------------------------------
    # URLs
    # -----------------------------------------

    urls = extract_urls(text)


    if urls:

        points = min(
            len(urls) * 8,
            24
        )

        risk += points

        reasons.append(
            f"{len(urls)} URL(s) detected"
        )


    # -----------------------------------------
    # Urgency
    # -----------------------------------------

    urgency_found = [

        word

        for word in URGENT_PATTERNS

        if word in text

    ]


    if urgency_found:

        risk += 12

        reasons.append(
            "Urgency-based language detected"
        )


    # -----------------------------------------
    # Credential request
    # -----------------------------------------

    credential_found = [

        word

        for word in CREDENTIAL_PATTERNS

        if word in text

    ]


    if credential_found:

        risk += 20

        reasons.append(
            "Credential or OTP request detected"
        )


    # -----------------------------------------
    # Sender domain
    # -----------------------------------------

    domain = extract_email_domain(
        sender
    )


    suspicious_domains = [

        "tempmail",
        "mailinator",
        "example",
        "test"

    ]


    if domain:

        for suspicious_domain in suspicious_domains:

            if suspicious_domain in domain:

                risk += 10

                reasons.append(
                    "Sender domain requires verification"
                )

                break


    return (

        min(risk, 100),

        suspicious_words,

        urls,

        reasons

    )


# =========================================================
# ML PREDICTION
# =========================================================

def ml_prediction(subject, body):

    if model is None or vectorizer is None:

        return None


    try:

        text = (
            f"{subject} {body}"
        )


        transformed = (
            vectorizer.transform([text])
        )


        prediction = model.predict(
            transformed
        )[0]


        confidence = None


        if hasattr(
            model,
            "predict_proba"
        ):

            probabilities = (
                model.predict_proba(
                    transformed
                )[0]
            )


            confidence = round(
                max(probabilities) * 100,
                2
            )


        return {

            "prediction":
                str(prediction),

            "confidence":
                confidence

        }


    except Exception as error:

        print(
            "ML prediction error:",
            error
        )

        return None


# =========================================================
# COMPLETE EMAIL ANALYSIS
# =========================================================

def analyze_email(
    sender,
    subject,
    body
):

    # -----------------------------------------
    # Local analysis
    # -----------------------------------------

    risk, suspicious_words, urls, reasons = (
        calculate_risk(
            sender,
            subject,
            body
        )
    )


    # -----------------------------------------
    # Google Safe Browsing
    # -----------------------------------------

    google_result = (
        check_google_safe_browsing(
            urls
        )
    )


    google_threats = (
        google_result["threats"]
    )


    # -----------------------------------------
    # Google threat increases risk
    # -----------------------------------------

    if google_threats:

        risk = min(
            risk + 30,
            100
        )

        reasons.append(
            "Google Safe Browsing reported a URL threat"
        )


    # -----------------------------------------
    # ML prediction
    # -----------------------------------------

    ml_result = ml_prediction(
        subject,
        body
    )


    # =================================================
    # FINAL PREDICTION
    # =================================================

    if ml_result is not None:

        raw_prediction = (
            ml_result["prediction"]
            .lower()
        )


        if raw_prediction in [
            "fake",
            "phishing",
            "spam",
            "1"
        ]:

            prediction = "LIKELY FAKE"


        elif raw_prediction in [
            "real",
            "legitimate",
            "ham",
            "0"
        ]:

            prediction = "LIKELY REAL"


        else:

            prediction = "SUSPICIOUS"


        confidence = (
            ml_result["confidence"]
        )


        if confidence is None:

            confidence = 70


        # Security signals override
        # an apparently safe ML result.

        if risk >= 65:

            prediction = "LIKELY FAKE"


        elif risk >= 35:

            prediction = "SUSPICIOUS"


    else:

        # -----------------------------------------
        # Fallback analyzer
        # -----------------------------------------

        if risk >= 65:

            prediction = "LIKELY FAKE"

            confidence = min(
                70 + risk // 3,
                97
            )


        elif risk >= 35:

            prediction = "SUSPICIOUS"

            confidence = min(
                62 + risk // 4,
                89
            )


        else:

            prediction = "LIKELY REAL"

            confidence = max(
                72,
                94 - risk // 2
            )


    # =================================================
    # THREAT LEVEL
    # =================================================

    if risk >= 65:

        threat_level = "HIGH"

        warning = (
            "High-risk indicators detected. "
            "Avoid unknown links and never share "
            "passwords, OTPs or financial information."
        )


    elif risk >= 35:

        threat_level = "MEDIUM"

        warning = (
            "Suspicious indicators were detected. "
            "Verify the sender and website independently "
            "before taking action."
        )


    else:

        threat_level = "LOW"

        warning = (
            "No major phishing indicators were detected. "
            "Still verify important requests."
        )


    # =================================================
    # EXPLANATION
    # =================================================

    if reasons:

        reason = "; ".join(
            reasons
        )

    else:

        reason = (
            "No major suspicious indicators "
            "were found."
        )


    # =================================================
    # RETURN RESULT
    # =================================================

    return {

        "sender":
            sender,

        "prediction":
            prediction,

        "confidence":
            round(
                float(confidence),
                2
            ),

        "risk_score":
            risk,

        "threat_level":
            threat_level,

        "suspicious_words":
            suspicious_words,

        "links":
            urls,

        "google_checked":
            google_result["checked"],

        "google_threats":
            len(google_threats),

        "google_message":
            google_result["message"],

        "warning":
            warning,

        "reason":
            reason,

        "ml_model_used":
            model is not None

    }


# =========================================================
# ANALYZE API
# =========================================================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )


    sender = str(
        data.get(
            "sender",
            ""
        )
    ).strip()


    subject = str(
        data.get(
            "subject",
            ""
        )
    ).strip()


    body = str(
        data.get(
            "body",
            ""
        )
    ).strip()


    if not subject and not body:

        return jsonify({

            "error":
                "Email subject or body is required."

        }), 400


    result = analyze_email(

        sender,

        subject,

        body

    )


    return jsonify(result)


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route(
    "/health",
    methods=["GET"]
)
def health():

    return jsonify({

        "status":
            "online",

        "service":
            "AI MailGuard",

        "ml_model_loaded":
            model is not None,

        "google_safe_browsing":
            bool(
                GOOGLE_SAFE_BROWSING_KEY
            )

    })


# =========================================================
# FRONTEND
# =========================================================

@app.route("/")
def home():

    return send_from_directory(
        ".",
        "index.html"
    )


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True

      )
