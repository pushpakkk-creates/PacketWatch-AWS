# PacketWatch — Network Traffic Analysis AWS Lab

A full-stack, Docker-free educational project with a custom HTML/CSS/JavaScript dashboard and a Python FastAPI backend. It analyzes labelled network-flow CSVs and classifies records as BENIGN or ATTACK.

## Stack
- Frontend: HTML5, CSS3, vanilla JavaScript, Chart.js
- Backend: Python 3.11, FastAPI, Uvicorn
- Data/ML: Pandas, NumPy, scikit-learn Random Forest, Joblib
- AWS: EC2 Ubuntu, Security Groups, systemd; CloudWatch

## Structure
```text
PacketWatch_Web_AWS_Lab/
├── app/
│   └── main.py
├── static/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── models/
├── reports/
├── data/raw/
├── data/processed/
├── requirements.txt
└── README.md
```

## Local run on Windows
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Open http://127.0.0.1:8000. Interactive API docs: http://127.0.0.1:8000/docs.

If Python 3.11 isn't installed, install a supported Python version and adjust the `py` command accordingly.

## Synthetic dataset generator
The Model training page includes a **Generate sample** button with 100, 250, and 500 row options. It creates a labelled CSV using Faker-generated private IP addresses and timestamps plus synthetic flow statistics. The generated CSV is saved to `data/raw/generated_traffic.csv` and automatically selected in the UI, so you can inspect it and train without downloading a large dataset. Traffic analysis also has a **Generate fresh sample** button.

**Important:** generated records are artificial and only validate the app's end-to-end workflow. Metrics from this data are not evidence of real-world intrusion-detection performance.

## Dataset
Official CIC-IDS2017 page: https://www.unb.ca/cic/datasets/ids-2017.html
Start with a labelled flow CSV containing `Label`. The app reads at most 100,000 rows per upload for the initial demo.

## AWS deployment without Docker

### 1. Launch EC2
- Ubuntu Server 24.04 LTS
- `t3.small` for a light demo; a larger instance may be needed for training
- 20 GiB gp3 storage
- Security Group: SSH TCP 22 from My IP; app TCP 8000 from My IP for the initial lab demo
- Keep your `.pem` key secure

### 2. SSH from PowerShell
```powershell
ssh -i .\packetwatch-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

### 3. Install system dependencies on EC2
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

### 4. Transfer project
Push the source to your own GitHub repository (exclude datasets, model files and `.venv`), then:
```bash
git clone YOUR_REPOSITORY_URL
cd YOUR_REPOSITORY_DIRECTORY
```
Or use `scp` from Windows to copy the project directory.

### 5. Install Python packages
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
mkdir -p models reports
```

### 6. Test the app
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Open `http://YOUR_EC2_PUBLIC_IP:8000` from an allowed IP. Press Ctrl+C when the test succeeds.

### 7. Configure systemd
From project root, run `pwd` to confirm its full path. If it is `/home/ubuntu/PacketWatch_Web_AWS_Lab`, create:
```bash
sudo nano /etc/systemd/system/packetwatch.service
```
Paste:
```ini
[Unit]
Description=PacketWatch Network Traffic Lab
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/PacketWatch_Web_AWS_Lab
Environment=PYTHONUNBUFFERED=1
ExecStart=/home/ubuntu/PacketWatch_Web_AWS_Lab/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```
Adjust paths if the repository directory differs. Save with Ctrl+O, Enter, Ctrl+X. Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now packetwatch
sudo systemctl status packetwatch --no-pager
sudo journalctl -u packetwatch -f
```

## AWS lab evidence
Capture screenshots of:
1. EC2 running with status checks passed
2. Security Group inbound rules restricted to your IP
3. SSH terminal with Python version and active `packetwatch` service
4. Browser showing the app through EC2 public IPv4
5. Model training metrics and traffic analysis results

## Safety and limitations
- This app analyzes uploaded flow CSVs; it does not capture live packets or block traffic.
- This is an educational baseline, not a production intrusion detection system.
- A random row split may overstate generalization. Test on separate captures/days for stronger evaluation.
- Do not expose port 8000 publicly for a real deployment without HTTPS, authentication, and appropriate access controls.
- EC2, EBS and public IPv4 can incur charges. Stop/terminate resources after the lab; EBS may still incur charges while stopped.
- Never commit AWS credentials, private keys, datasets, or generated models to GitHub.
