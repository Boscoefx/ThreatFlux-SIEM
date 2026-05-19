import subprocess
import webbrowser
import os
import re
from flask import Flask, render_template, jsonify, request

# Database Connection
from src.database.db_connection import get_database

app = Flask(__name__)

# Global process tracker
current_task_process = None

# ✅ Correct Virtual Environment Python Path
VENV_PYTHON = "/home/kali/Downloads/Cyber-Batch16.1-G4-TIP-Platform-main/src/venv/bin/python"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/health')
def health():
    return jsonify({"status": "running"})


@app.route('/execute/<task>')
def execute_task(task):

    global current_task_process

    target_url = request.args.get('target', 'google.com')

    # ✅ Commands
    commands = {

        "intel": [
            VENV_PYTHON,
            "-m",
            "src.main"
        ],

        "enforce": [
            "sudo",
            VENV_PYTHON,
            "-m",
            "src.processors.policy_enforcer"
        ],

        "test": [
            "sudo",
            VENV_PYTHON,
            "-m",
            "src.tests.pen_test_sim",
            target_url
        ],

        "auto_test": [
            "sudo",
            VENV_PYTHON,
            "-m",
            "src.tests.auto_pentest"
        ],

        "rollback": [
            "bash",
            "-c",
            f"echo 'yes' | sudo {VENV_PYTHON} -m src.utils.rollback"
        ]
    }

    # Invalid Task
    if task not in commands:

        return jsonify({
            "output": "Invalid Task Requested",
            "status": "error"
        }), 400

    try:

        # Start Process
        current_task_process = subprocess.Popen(
            commands[task],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        stdout, stderr = current_task_process.communicate(timeout=300)

        status = "open"

        # Packet Loss Detection
        if "100% packet loss" in stdout or "0 received" in stdout:
            status = "blocked"

        # Success
        if current_task_process.returncode == 0:

            return jsonify({
                "output": stdout,
                "status": status
            })

        # Error
        else:

            return jsonify({
                "output": f"PROCESS ERROR:\n{stderr or stdout}",
                "status": "error"
            })

    except subprocess.TimeoutExpired:

        if current_task_process:

            os.system(f"sudo kill -9 {current_task_process.pid}")

            current_task_process = None

        return jsonify({
            "output": "[!] Phase Timeout: Task exceeded 300 seconds.",
            "status": "error"
        })

    except Exception as e:

        return jsonify({
            "output": f"Backend Exception: {str(e)}",
            "status": "error"
        }), 500


@app.route('/execute/unblock')
def unblock_ip():

    target_ip = request.args.get('target')

    if not target_ip:

        return jsonify({
            "output": "No IP provided.",
            "status": "error"
        }), 400

    try:

        cmd = [
            "sudo",
            "iptables",
            "-D",
            "INPUT",
            "-s",
            target_ip,
            "-j",
            "DROP"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:

            return jsonify({
                "output": f"[+] SUCCESS: {target_ip} unblocked.",
                "status": "open"
            })

        else:

            return jsonify({
                "output": f"[-] FAILED: Rule not found for {target_ip}.",
                "status": "error"
            })

    except Exception as e:

        return jsonify({
            "output": f"Error: {str(e)}",
            "status": "error"
        }), 500


@app.route('/execute/manual_block')
def manual_block():

    target_ip = request.args.get('target')

    if not target_ip:

        return jsonify({
            "output": "No IP provided.",
            "status": "error"
        }), 400

    try:

        # Check Existing Rule
        check = subprocess.run(
            [
                "sudo",
                "iptables",
                "-C",
                "INPUT",
                "-s",
                target_ip,
                "-j",
                "DROP"
            ],
            capture_output=True
        )

        if check.returncode == 0:

            return jsonify({
                "output": f"[!] {target_ip} already blocked.",
                "status": "blocked"
            })

        # Add Rule
        cmd = [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-s",
            target_ip,
            "-j",
            "DROP"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:

            return jsonify({
                "output": f"[+] MANUAL BLOCK SUCCESS: {target_ip}",
                "status": "blocked"
            })

        else:

            return jsonify({
                "output": f"[-] FAILED: {result.stderr}",
                "status": "error"
            })

    except Exception as e:

        return jsonify({
            "output": f"Error: {str(e)}",
            "status": "error"
        }), 500


@app.route('/terminate_task', methods=['POST'])
def terminate_task():

    global current_task_process

    if current_task_process and current_task_process.poll() is None:

        try:

            os.system(f"sudo kill -9 {current_task_process.pid}")

            current_task_process = None

            return jsonify({
                "success": True,
                "message": "Task terminated safely."
            })

        except Exception as e:

            return jsonify({
                "success": False,
                "message": f"Kill failed: {str(e)}"
            })

    return jsonify({
        "success": False,
        "message": "No active process."
    })


@app.route('/execute/view_blocked')
def view_blocked():

    try:

        result = subprocess.run(
            ['sudo', 'iptables', '-nL', 'INPUT'],
            capture_output=True,
            text=True
        )

        lines = result.stdout.split('\n')

        live_ips = []

        for line in lines[2:]:

            parts = line.split()

            if len(parts) >= 4 and parts[0] == "DROP":

                ip = parts[3].split('/')[0]

                if ip != "0.0.0.0":
                    live_ips.append(ip)

        if not live_ips:
            return jsonify({"items": []})

        # MongoDB
        db = get_database()

        if db is None:

            return jsonify({
                "items": [
                    {
                        "indicator": ip,
                        "url": "DB Offline",
                        "score": "!"
                    } for ip in live_ips
                ]
            })

        collection = db["threat_indicators"]

        enriched_list = []

        cursor = collection.find(
            {
                "indicator": {
                    "$in": live_ips
                }
            },
            {
                "_id": 0,
                "indicator": 1,
                "risk_score": 1,
                "source": 1,
                "url": 1
            }
        ).sort("risk_score", -1).limit(50)

        for doc in cursor:

            display_info = (
                doc.get("url")
                or doc.get("source")
                or "Enriched Threat"
            )

            enriched_list.append({
                "indicator": doc.get("indicator"),
                "url": display_info,
                "score": doc.get("risk_score", 0)
            })

        return jsonify({
            "items": enriched_list
        })

    except Exception as e:

        return jsonify({
            "output": f"Kernel Error: {str(e)}",
            "status": "error"
        })


if __name__ == '__main__':

    webbrowser.open("http://127.0.0.1:5000")

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False
    )
