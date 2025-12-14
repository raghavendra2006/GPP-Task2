# GPP Task 2 – Secure Microservice Implementation (PKI + Docker)

This repository contains my completed implementation for **GPP Task 2**, focusing on a secure microservice architecture using **Public Key Infrastructure (PKI)**, **encrypted seed validation**, and **containerized deployment with Docker**.

The project demonstrates:
- Secure identity verification using asymmetric cryptography
- Encrypted commit validation
- Dockerized microservice setup
- End-to-end submission integrity verification

---

## 📁 Project Structure

```text
GPP-Task2/
├── app/
│   ├── main.py
│   └── requirements.txt
├── keys/
│   ├── student_private.pem
│   ├── student_public.pem
│   └── instructor_public.pem
├── scripts/
│   ├── sign_commit.sh
│   └── encrypt_signature.sh
├── Dockerfile
├── docker-compose.yml
├── encrypted_seed.txt
├── README.md
🚀 Features
🔐 PKI-based authentication

✍️ Commit hash signing using student private key

🔒 Encrypted signature using instructor public key

🐳 Docker & Docker Compose support

📦 Reproducible and verifiable microservice build

🛠️ Tech Stack
Language: Python

Security: OpenSSL (RSA, PKI)

Containerization: Docker, Docker Compose

Version Control: Git & GitHub

🧪 Setup & Run Instructions
1️⃣ Clone the Repository
bash
Copy code
git clone https://github.com/raghavendra2006/GPP-Task2.git
cd GPP-Task2
2️⃣ Build & Run with Docker
bash
Copy code
docker-compose up --build
3️⃣ Stop Services
bash
Copy code
docker-compose down
🔐 Cryptographic Workflow
Generate RSA key pair (student)

Receive encrypted seed from Instructor API

Commit final code to GitHub

Extract commit hash

Sign commit hash using student_private.pem

Encrypt signature using instructor_public.pem

Submit encrypted signature and keys via portal

📌 Submission Information
✅ Required Submission Items
Item	Description
GitHub Repository URL	https://github.com/raghavendra2006/GPP-Task2
Commit Hash	Generated using git log -1 --format=%H
Encrypted Commit Signature	Base64 encoded, single-line encrypted signature
Student Public Key	Contents of student_public.pem
Encrypted Seed	Contents of encrypted_seed.txt
Docker Image URL	(Optional – if pushed to registry)

📜 Commands Used
Get Commit Hash
bash
Copy code
git log -1 --format=%H
Sign Commit Hash
bash
Copy code
openssl dgst -sha256 -sign keys/student_private.pem commit.txt > signature.bin
Encrypt Signature
bash
Copy code
openssl rsautl -encrypt -pubin \
  -inkey keys/instructor_public.pem \
  -in signature.bin \
  -out encrypted_signature.bin
Base64 Encode
bash
Copy code
base64 encrypted_signature.bin > encrypted_signature.txt
🧠 Learning Outcomes
Practical understanding of PKI & asymmetric encryption

Secure software submission pipelines

Dockerized microservice deployment

Cryptographic integrity verification

👤 Author
PATCHIPULUSU LEELA KRISHNA RAGHAVENDRA
GitHub: raghavendra2006

✅ Status
✔ Task Completed
✔ All required submission artifacts included
✔ Ready for evaluation

yaml
Copy code

---

If you want, I can also:
- ✅ Customize it **exactly to your file names**
- ✅ Add **badges (Docker, GitHub, Status)**
- ✅ Simplify it for **ATS / academic evaluation**
- ✅ Verify your repo for **missing submission items**

Just tell me 👍
