from flask import Flask, render_template, request
from detector import detect_fake
import os

app = Flask(__name__)
UPLOAD_PATH = "uploads"
os.makedirs(UPLOAD_PATH, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        apkfile = request.files.get("apkfile")
        if apkfile and apkfile.filename.endswith(".apk"):
            save_path = os.path.join(UPLOAD_PATH, "uploaded_app.apk")
            apkfile.save(save_path)
            result = detect_fake(save_path)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
