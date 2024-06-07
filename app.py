from flask import (
    Flask,
    request,
    make_response,
    redirect,
    url_for,
    session,
    render_template,
    send_from_directory,
)
import base64
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = "super_secret_key"  # Necesario para utilizar variables de sesión


def encode_base64(plain_text):
    message_bytes = plain_text.encode("utf-8")
    base64_bytes = base64.b64encode(message_bytes)
    return base64_bytes.decode("utf-8")


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("home"))
        return func(*args, **kwargs)

    return wrapper


@app.route("/", methods=["GET", "POST"])
def home():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username and password:
            # Vulnerable a SQL Injection
            valid_injections = [
                "admin' --",
                "admin' #",
                "admin'/*",
                "' OR 1=1 --",
                "' OR 1=1 #",
                "' OR 1=1 /*",
                "') or '1'='1--",
                "') or ('1'='1--",
            ]
            if username in valid_injections or password in valid_injections:
                session["logged_in"] = True
                return redirect(url_for("success"))
            else:
                error = "Invalid credentials!"
    return render_template("home.html", error=error)


@app.route("/success")
@login_required
def success():
    return render_template("success.html")


@app.route("/download_xss")
@login_required
def download_xss():
    script = """
    fetch('/execute_xss', {
        headers: {
            'X-Execute-XSS': 'true'
        }
    }).then(response => {
        if (response.ok) {
            window.location.href = '/execute_xss_redirect';
        }
    });
    """
    response = make_response(script)
    response.headers["Content-Disposition"] = "attachment; filename=xss_script.js"
    response.mimetype = "application/javascript"
    return response


@app.route("/execute_xss")
@login_required
def execute_xss():
    if request.headers.get("X-Execute-XSS") == "true":
        return make_response("XSS executed successfully!")
    else:
        return "Unauthorized access", 403


@app.route("/execute_xss_redirect")
@login_required
def execute_xss_redirect():
    message = "segti{d3crypt_c00k13s_15_fun}"
    encrypted_message = encode_base64(message)
    response = make_response(render_template("execute_xss.html"))
    response.set_cookie("session", encrypted_message, samesite="None", secure=True)
    return response


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
