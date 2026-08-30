from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from strawberry.fastapi import GraphQLRouter

from app.database import init_db, get_db
from app.graphql_schema import schema
from app.gateway import bola_gateway, BOLAException
from app.auth import create_access_token

app = FastAPI(title="GraphQL BOLA Gateway Prototype")
templates = Jinja2Templates(directory="templates")

@app.on_event("startup")
def startup_event():
    init_db()

@app.exception_handler(BOLAException)
async def bola_exception_handler(request: Request, exc: BOLAException):
    return JSONResponse(
        status_code=403,
        content={
            "status": "BLOCKED",
            "reason": "BOLA detected",
            "message": str(exc)
        }
    )

# The GraphQL Router is protected by our BOLA Gateway dependency
graphql_app = GraphQLRouter(schema, context_getter=None, dependencies=[Depends(bola_gateway)])
app.include_router(graphql_app, prefix="/graphql")

@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE email = ? AND password = ?", (email, password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        token = create_access_token(user["id"], user["name"])
        return {
            "access_token": token, 
            "token_type": "bearer", 
            "user_id": user["id"], 
            "username": user["name"]
        }
    return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})

@app.get("/logs")
async def get_logs():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, user_id, object_id, decision, reason FROM audit_logs ORDER BY timestamp DESC")
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

@app.get("/", response_class=HTMLResponse)
async def serve_demo(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
