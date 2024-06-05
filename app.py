from flask import Flask, request, make_response, redirect, url_for, session
import base64

app = Flask(__name__)
app.secret_key = "super_secret_key"  # Necesario para utilizar variables de sesión


def encode_base64(plain_text):
    message_bytes = plain_text.encode("utf-8")
    base64_bytes = base64.b64encode(message_bytes)
    return base64_bytes.decode("utf-8")


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username and password:
            # Vulnerable a SQL Injection
            if username == "' OR 1=1 --" and password == "' OR 1=1 --":
                session["logged_in"] = True
                return redirect(url_for("success"))
        return "Invalid login!"

    return """
        <h2>Login</h2>
        <form method="post">
            Username: <input type="text" name="username">
            Password: <input type="password" name="password">
            <input type="submit" value="Login">
        </form>
    """


@app.route("/success")
def success():
    if not session.get("logged_in"):
        return "Unauthorized access", 403
    return """
        <h2>Success!</h2>
        <p>You have successfully exploited SQL Injection.</p>
        <form action="/download_xss" method="get">
            <button type="submit">Download XSS Script</button>
        </form>
    """


@app.route("/download_xss")
def download_xss():
    if not session.get("logged_in"):
        return "Unauthorized access", 403
    script = """
    fetch('/execute_xss', {
        headers: {
            'X-Execute-XSS': 'true'
        }
    }).then(response => {
        if (response.ok) {
            alert('XSS executed successfully!');
        }
    });
    """
    response = make_response(script)
    response.headers["Content-Disposition"] = "attachment; filename=xss_script.js"
    response.mimetype = "application/javascript"
    return response


@app.route("/execute_xss")
def execute_xss():
    if request.headers.get("X-Execute-XSS") == "true":
        message = "segti{XSS_3x3cut3d}"
        encrypted_message = encode_base64(message)
        response = make_response("XSS executed successfully, cookie has been set!")
        response.set_cookie("session", encrypted_message)
        return response
    else:
        return "Unauthorized access", 403


if __name__ == "__main__":
    app.run(debug=True)
