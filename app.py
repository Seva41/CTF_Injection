from flask import (
    Flask,
    request,
    render_template_string,
    make_response,
    redirect,
    url_for,
)
import hashlib

app = Flask(__name__)

# Simulated database
users = {"admin": "5f4dcc3b5aa765d61d8327deb882cf99"}  # 'password' MD5 hash

# Flag storage
final_flag = "segti{UNIQUE_FINAL_FLAG}"

# Admin only file content
admin_file_content = final_flag


def hash_md5(text):
    md5_hash = hashlib.md5()
    md5_hash.update(text.encode("utf-8"))
    return md5_hash.hexdigest()


@app.route("/")
def home():
    session_value = hash_md5("th1s_1s_a_s3cur3_c00ki3")
    print(
        f"MD5 hash being set in the cookie: {session_value}"
    )  # Print the hash to verify
    response = make_response(
        """
    <h1>Welcome to SecureMart</h1>
    <p>Navigate through the site to find and exploit vulnerabilities.</p>
    <ul>
        <li><a href="/comment">Comment Section (XSS)</a></li>
        <li><a href="/search">Product Search (SQL Injection)</a></li>
        <li><a href="/admin">Admin Page (Session Cookie)</a></li>
    </ul>
    """
    )
    # Set a session cookie for demonstration purposes
    response.set_cookie("session", session_value)
    return response


# XSS vulnerable comment section
@app.route("/comment", methods=["GET", "POST"])
def comment():
    if request.method == "POST":
        comment = request.form.get("comment")
        return render_template_string(f"Comment received: {comment}")
    return """
        <h2>Leave a Comment</h2>
        <form method="post">
            Comment: <input type="text" name="comment">
            <input type="submit">
        </form>
        <a href="/">Back to Home</a>
    """


# Simulated admin profile page
@app.route("/admin")
def admin():
    if request.cookies.get("session") == "admin_session_cookie":
        return f"Welcome, admin! <a href='/admin/file'>Access admin file</a>"
    return "Access denied! <a href='/'>Back to Home</a>"


# SQLi vulnerable search page
@app.route("/search")
def search():
    query = request.args.get("query", "")
    if query:
        if query == "' OR 1=1 --":
            return f"Users: {users}"
    return """
        <h2>Search Products</h2>
        <form>
            Search: <input type="text" name="query">
            <input type="submit">
        </form>
        <a href="/">Back to Home</a>
    """


# Admin file access
@app.route("/admin/file", methods=["GET", "POST"])
def admin_file():
    if request.cookies.get("session") == "admin_session_cookie":
        if request.method == "POST":
            password = request.form.get("password")
            if password == "password":  # The password recovered from the MD5 hash
                return f"Admin file content: {admin_file_content}"
            else:
                return "Incorrect password! <a href='/admin/file'>Try again</a>"
        return """
            <h2>Enter Password to Access Admin File</h2>
            <form method="post">
                Password: <input type="password" name="password">
                <input type="submit" value="Submit">
            </form>
            <a href="/admin">Back to Admin</a>
        """
    return "Access denied! <a href='/'>Back to Home</a>"


@app.route("/favicon.ico")
def favicon():
    return app.send_static_file("favicon.ico")


if __name__ == "__main__":
    app.run(debug=True)
