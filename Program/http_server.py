import tkinter as tk
from tkinter import messagebox
import base64


def decode_base64(encoded_text):
    try:
        base64_bytes = encoded_text.encode("utf-8")
        message_bytes = base64.b64decode(base64_bytes)
        return message_bytes.decode("utf-8")
    except Exception as e:
        return f"Error: {str(e)}"


def on_decrypt():
    encoded_message = entry.get()
    if encoded_message:
        decoded_message = decode_base64(encoded_message)
        messagebox.showinfo("Decrypted Message", decoded_message)
    else:
        messagebox.showwarning("Input Error", "Please enter the encoded message.")


# Create the main window
root = tk.Tk()
root.title("Cookie Decoder")
root.geometry("450x280")

# Create and place the widgets
label = tk.Label(root, text="Enter the encoded cookie:", font=("Arial", 12))
label.pack(pady=10)

entry = tk.Entry(root, width=25, font=("Arial", 12))
entry.pack(pady=10)

button = tk.Button(
    root, text="Decrypt", command=on_decrypt, font=("Arial", 12), bg="blue", fg="white"
)
button.pack(pady=20)

# Watermark
watermark = tk.Label(
    root,
    text="Made by Seva41\nSeguridad en TI 2024",
    font=("Arial", 8),
    fg="grey",
    anchor="se",
)
watermark.place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-10)

# Run the application
root.mainloop()
