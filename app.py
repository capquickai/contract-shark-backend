import os
import secrets
import string
import json
import base64
import io
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
import stripe
from groq import Groq
import PyPDF2

app = Flask(__name__)
CORS(app)

# ── Config ────────────────────────────────────────────────────────────────────
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://contractshark.netlify.app")

groq_client = Groq(api_key=GROQ_API_KEY)

# ── Token storage (in-memory — works fine for this scale) ─────────────────────
# token -> { used: bool, created_at: datetime, email: str }
tokens = {}


def generate_token():
    """Generate a readable 8-char token like XKCD-9F2A"""
    chars = string.ascii_uppercase + string.digits
    part1 = ''.join(secrets.choice(chars) for _ in range(4))
    part2 = ''.join(secrets.choice(chars) for _ in range(4))
    return f"{part1}-{part2}"


# ── Stripe webhook ─────────────────────────────────────────────────────────────
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        return jsonify({"error": "Invalid signature"}), 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        customer_email = session.get("customer_details", {}).get("email", "")

        # Generate one-time token
        token = generate_token()
        tokens[token] = {
            "used": False,
            "created_at": datetime.utcnow(),
            "email": customer_email
        }

        # Send email with token
        send_token_email(customer_email, token)

        print(f"Token generated for {customer_email}: {token}")

    elif event["type"] == "payment_intent.succeeded":
        # Also handle direct payment intents
        pass

    return jsonify({"status": "ok"})


def send_token_email(email, token):
    """Send access token via email using SendGrid or similar."""
    # For now we log it — swap in SendGrid/Resend/Mailgun below
    print(f"EMAIL TO: {email} | TOKEN: {token}")

    sendgrid_key = os.environ.get("SENDGRID_API_KEY")
    if not sendgrid_key:
        print("No SendGrid key — token logged above. Add SENDGRID_API_KEY to env.")
        return

    try:
        import sendgrid
        from sendgrid.helpers.mail import Mail

        sg = sendgrid.SendGridAPIClient(api_key=sendgrid_key)
        message = Mail(
            from_email="noreply@contractshark.ai",
            to_emails=email,
            subject="🦈 Your Contract Shark Access Code",
            html_content=f"""
            <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; background: #05080f; color: #f0f4f8; padding: 32px; border-radius: 8px;">
                <h1 style="color: #00d4e8; font-size: 2rem; margin-bottom: 8px;">🦈 Contract Shark</h1>
                <p style="color: #718096; margin-bottom: 24px;">Your analysis is ready. Use the code below to unlock your results.</p>
                <div style="background: #0d1420; border: 1px solid #00d4e8; border-radius: 8px; padding: 24px; text-align: center; margin-bottom: 24px;">
                    <p style="color: #718096; font-size: 0.85rem; margin-bottom: 8px; letter-spacing: 2px;">YOUR ACCESS CODE</p>
                    <div style="font-family: monospace; font-size: 2rem; color: #00d4e8; letter-spacing: 4px; font-weight: bold;">{token}</div>
                </div>
                <p style="color: #a0aec0; font-size: 0.9rem;">Go back to <a href="{FRONTEND_URL}" style="color: #00d4e8;">Contract Shark</a>, click "Already paid? Enter your access code" and enter the code above.</p>
                <p style="color: #4a5568; font-size: 0.8rem; margin-top: 24px;">This code works once and expires in 24 hours.</p>
            </div>
            """
        )
        sg.send(message)
        print(f"Email sent to {email}")
    except Exception as e:
        print(f"Email send failed: {e}")


# ── Token verification ─────────────────────────────────────────────────────────
@app.route("/verify-token", methods=["POST"])
def verify_token():
    data = request.json or {}
    token = data.get("token", "").strip().upper()

    if not token:
        return jsonify({"valid": False, "message": "No token provided."})

    if token not in tokens:
        return jsonify({"valid": False, "message": "Invalid access code. Check your email and try again."})

    token_data = tokens[token]

    if token_data["used"]:
        return jsonify({"valid": False, "message": "This access code has already been used."})

    # Check expiry (24 hours)
    age = datetime.utcnow() - token_data["created_at"]
    if age > timedelta(hours=24):
        del tokens[token]
        return jsonify({"valid": False, "message": "This access code has expired. Contact support."})

    return jsonify({"valid": True})


# ── Analysis endpoint ──────────────────────────────────────────────────────────
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json or {}
    token = data.get("token", "").strip().upper()
    contract_type = data.get("contract_type", "Contract")
    pdf_base64 = data.get("pdf_base64")
    contract_text = data.get("contract_text", "")

    # Verify token again server-side
    if token not in tokens:
        return jsonify({"error": "Invalid access code."}), 403

    token_data = tokens[token]

    if token_data["used"]:
        return jsonify({"error": "This access code has already been used."}), 403

    age = datetime.utcnow() - token_data["created_at"]
    if age > timedelta(hours=24):
        del tokens[token]
        return jsonify({"error": "Access code expired."}), 403

    # Extract text from PDF if provided
    if pdf_base64:
        try:
            pdf_bytes = base64.b64decode(pdf_base64)
            reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
            contract_text = "\n".join(page.extract_text() or "" for page in reader.pages).strip()
        except Exception as e:
            return jsonify({"error": f"Could not read PDF: {str(e)}"}), 400

    if not contract_text or len(contract_text) < 100:
        return jsonify({"error": "Contract text is too short or could not be extracted."}), 400

    # Mark token as used BEFORE analysis (prevents double-use during slow analysis)
    tokens[token]["used"] = True

    # Run Groq analysis
    try:
        result = analyze_contract(contract_text, contract_type)
        return jsonify(result)
    except Exception as e:
        # If analysis fails, un-use the token so they can try again
        tokens[token]["used"] = False
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


def analyze_contract(contract_text, contract_type):
    trimmed = contract_text[:6000]

    prompt = f"""You are a sharp, no-BS contract attorney reviewing a {contract_type}.
Your job is to protect the person signing this contract.

Analyze this contract and respond in EXACTLY this format — nothing else:

SCORE: <number 0-100 where 100 = completely fair, 0 = total scam>
VERDICT: <one sentence, blunt, plain English summary of how fair this contract is>

RED_FLAGS:
- <specific clause or issue that could seriously harm the signer>
- <add as many as needed, or write NONE>

WATCH_OUT:
- <clauses that aren't terrible but worth knowing about>
- <add as many as needed, or write NONE>

NEGOTIATE:
- <specific things the signer should try to negotiate>
- <add as many as needed, or write NONE>

PLAIN_ENGLISH:
<3-5 sentence plain English summary of what this contract says>

Contract:
{trimmed}"""

    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1500,
        temperature=0.2,
    )

    return parse_response(response.choices[0].message.content.strip())


def parse_response(raw):
    result = {
        "score": 50,
        "verdict": "Analysis complete.",
        "red_flags": [],
        "watch_out": [],
        "negotiate": [],
        "plain_english": ""
    }

    current_section = None
    plain_lines = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("SCORE:"):
            try:
                result["score"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("VERDICT:"):
            result["verdict"] = line.split(":", 1)[1].strip()
        elif line.startswith("RED_FLAGS:"):
            current_section = "red_flags"
        elif line.startswith("WATCH_OUT:"):
            current_section = "watch_out"
        elif line.startswith("NEGOTIATE:"):
            current_section = "negotiate"
        elif line.startswith("PLAIN_ENGLISH:"):
            current_section = "plain_english"
        elif line.startswith("- ") and current_section in ("red_flags", "watch_out", "negotiate"):
            item = line[2:].strip()
            if item.upper() != "NONE":
                result[current_section].append(item)
        elif current_section == "plain_english":
            plain_lines.append(line)

    result["plain_english"] = " ".join(plain_lines)
    return result


# ── Health check ───────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Contract Shark API"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
