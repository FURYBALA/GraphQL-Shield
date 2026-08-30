# GraphQL Shield: Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities

**Academic Project (25% Prototype)**
**Course**: Computer Communication and Network Security

## Team Members
| Name | Register Number |
| :--- | :--- |
| Agnihotram Chinmayanand | RA2311053010116 |
| B.V.Balanilavan | RA2311053010123 |
| Kapilesh.N | RA2311053010125 |
| Sakthivel | RA2311053010126 |

---

## 📖 Problem Statement
Broken Object Level Authorization (BOLA) is a severe vulnerability in APIs. It occurs when an application checks if a user is authenticated (e.g., using a JWT), but fails to verify if the user is *authorized* to access the specific object ID they requested. Attackers exploit this by simply changing object IDs in their requests to access data belonging to other users.

## 🚀 System Architecture
This 25% prototype implements a **Security Gateway** as a middleware layer situated before the GraphQL resolver. 
1. The gateway intercepts the incoming GraphQL request.
2. It validates the user's JWT to confirm identity.
3. It extracts the requested `object_id` from the GraphQL query variables.
4. It performs a real-time database check to verify the object's `owner_id`.
5. **Decision Engine**: If the user owns the object, it is ALLOWED. If not, it is BLOCKED (HTTP 403) before the request even reaches the GraphQL application layer.

## 🛠 Technology Stack
- **Backend Framework**: FastAPI (Python)
- **GraphQL Engine**: Strawberry
- **Database**: SQLite
- **Authentication**: PyJWT
- **Frontend Demo**: HTML, CSS, JavaScript (via Jinja2 Templates)

## ⚙️ Installation Steps

1. Open your terminal and navigate to this project folder.
2. It is recommended to create a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Mac/Linux:
   source venv/bin/activate
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## ▶️ How to Run

1. Run the FastAPI server using Uvicorn:
   ```bash
   uvicorn app.main:app --reload
   ```
2. The application will start and the database (`database.db`) will be automatically created and populated with sample data.
3. Open your browser and go to: **http://localhost:8000**

---

## 🧑‍🏫 Professor Demo Guide

Follow this exact sequence to demonstrate the project to your professor.

### STEP 1: Start the Application
Show that the server is running and open `http://localhost:8000` in the browser.

### STEP 2: Login as Alice
- **Email**: `alice@example.com`
- **Password**: `alice123`
- Click **Login**.
- *Explain*: Show that Alice receives a JWT token (authentication successful).

### STEP 3: Test Legitimate Access (ALLOW)
- In the GraphQL Request section, enter Object ID: `501` (Alice's object).
- Click **Send GraphQL Query**.
- *Expected Output*: **✓ ALLOWED — AUTHORIZED REQUEST**. The object data is returned.
- *Explain*: The gateway checked the database and verified Alice (User 101) owns Object 501.

### STEP 4: Demonstrate BOLA Attack (BLOCK)
- Alice is a malicious user trying to view Bob's data.
- Change the Object ID to: `601` (Bob's object).
- Click **Send GraphQL Query**.
- *Expected Output*: **✗ BLOCKED — BOLA DETECTED** (HTTP 403 Forbidden).
- *Explain*: The gateway intercepted the request, saw that Alice (101) was trying to access an object owned by Bob (102), and blocked it before the GraphQL resolver could process it.

### STEP 5: Show the Audit Logs
- Scroll down to the **Security Audit Logs** section.
- *Explain*: Show the professor how the gateway tracks every decision. 
  - `User 101 -> Object 501 -> ALLOW -> Owner`
  - `User 101 -> Object 601 -> BLOCK -> BOLA detected`

---

## 🔮 Future Enhancements
- Automatic schema-based ownership inference.
- Handling complex aliases and fragments.
- Advanced query normalization and global ID decoding.
- Deployment using Kubernetes/Docker.
- Integration of complex policy engines (e.g., OPA).
