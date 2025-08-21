from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from routers import auth, gmail_oauth, mailbox, agent, dashboard, account
from fastapi import FastAPI, Response
from utils.handlers import http_exception_handler, global_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException
from utils.handlers import http_exception_handler, global_exception_handler
from fastapi import FastAPI, HTTPException
from utils.handlers import http_exception_handler, global_exception_handler


app = FastAPI(redirect_slashes=False)

# CORS setup
ALLOWED_ORIGINS = [
    "http://localhost:3000",  # local dev
    "https://phishalert.azronix.xyz",  # deployed site
    #"*",  # Allows all origins (not recommended for production)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,   # NOT "*"
    allow_credentials=True,          # cookies => True
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"],
    allow_headers=["Content-Type","Authorization","X-CSRF-Token"],
)

# Public routes
app.include_router(auth.router, tags=["Authentication"])

# Secured routes
app.include_router(gmail_oauth.router, tags=["Gmail OAuth"])

app.include_router(mailbox.router, tags=["Mailbox"])

app.include_router(agent.router, tags=["Agent"])

app.include_router(dashboard.router, tags=["Dashboard"])

app.include_router(account.router, tags=["Account"])
#app.include_router(user_settings.router)


@app.get("/test")
def test():
    return {"message": "Test route working!"}

@app.get("/set-test-cookie")
def set_test_cookie(response: Response):
    response.set_cookie(
        key="test_cookie",
        value="this_is_a_test",
        httponly=True,
        secure=True,             # Secure: only over HTTPS
        samesite="none",         # Allow cross-site
        max_age=3600,            # 1 hour
        domain=".azronix.xyz",   # Make cookie available across subdomains
        path="/"
    )
    return {"message": "Test cookie set"}

@app.on_event("startup")
async def list_routes():
    print("\n📋 Registered Routes:")
    for route in app.routes:
        if hasattr(route, "methods"):
            print(f"{list(route.methods)}\t{route.path}")

app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, global_exception_handler)
