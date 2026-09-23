from flask import Flask, render_template, jsonify, request, Response
from sniffer import PacketSniffer
import threading
import csv
import io

app = Flask(__name__)
sniffer = PacketSniffer()
capture_thread = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    return jsonify(sniffer.get_stats())

@app.route("/api/packets")
def packets():
    limit = min(int(request.args.get("limit", 200)), 1000)
    return jsonify(sniffer.get_packets(limit))

@app.route("/api/packet/<int:packet_id>")
def packet_detail(packet_id):
    packet = sniffer.get_packet(packet_id)
    return jsonify(packet or {"error": "Packet not found"})

@app.route("/api/start", methods=["POST"])
def start():
    global capture_thread
    if not sniffer.running:
        sniffer.running = True
        capture_thread = threading.Thread(target=sniffer.capture, daemon=True)
        capture_thread.start()
    return jsonify({"running": sniffer.running})

@app.route("/api/stop", methods=["POST"])
def stop():
    sniffer.running = False
    return jsonify({"running": sniffer.running})

@app.route("/api/clear", methods=["POST"])
def clear():
    sniffer.clear()
    return jsonify({"success": True})

@app.route("/api/export")
def export_csv():
    rows = sniffer.get_packets(1000)
    output = io.StringIO()
    fields = ["id", "time", "source", "destination", "protocol", "network",
              "sport", "dport", "flags", "size"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=packet_capture.csv"}
    )

if __name__ == "__main__":
    print("Network Packet Sniffer & Analyzer Pro")
    print("Open http://127.0.0.1:5000 in your browser")
    app.run(host="127.0.0.1", port=5000, debug=False)
