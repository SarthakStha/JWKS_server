# JWKS Auth Server

## Setup

**1. Clone the repository**
```bash
git clone <repository-url>
cd <repository-folder>
```

**2. Create a virtual environment**
```bash
python -m venv venv
```

**3. Activate the virtual environment**

On macOS/Linux:
```bash
source venv/bin/activate
```
On Windows:
```bash
source venv\Scripts\activate
```

**4. Install dependencies**
```bash
pip install -r requirements.txt
```

---

## Running the Server

```bash
python server.py
```

## Running the Internal Tests
Note: The needs to run while the server is already running.
```bash
python test_server.py 
```

## Running the Gradebot (x86)
Note: Port 8080 is reserved in windows. This results in both the server and gradebot, throwing an error. While all the development was done on windows. Because of the port issue, the final test run for the internal tests and the gradebot was done on a mac.
```bash
./gradebot.exe project-2 --run="python main.py"
```

---

## Deliverables

### Grade Bot Evaluation

![POST /auth demo][image1]

### Internal Test coverage:

![GET /jwks.json demo][image2]

[image1]: images/gradebot.png
[image2]: images/internal_tests.png
