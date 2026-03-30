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

---

## Endpoints

### Grade Bot Evaluation

![POST /auth demo][image1]

### Internal Test coverage:

![GET /jwks.json demo][image2]

[image1]: path/to/image1.png
[image2]: path/to/image2.png
