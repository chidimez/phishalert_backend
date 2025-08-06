import os

from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from routers import auth, gmail_oauth
from fastapi import FastAPI, Request, Response
from utils.handlers import http_exception_handler, global_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException
from utils.handlers import http_exception_handler, global_exception_handler
from fastapi import FastAPI, HTTPException
from utils.handlers import http_exception_handler, global_exception_handler


app = FastAPI(redirect_slashes=False)

# CORS setup
origins = [
    "http://localhost:3000",  # local dev
    "https://phishalert.azronix.xyz",  # deployed site
    #"*",  # Allows all origins (not recommended for production)
]

ENV = os.getenv("ENV", "development")
IS_DEV = ENV == "development"


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "HEAD", "OPTIONS"],
    allow_headers=["*"],
    #allow_headers=["Access-Control-Allow-Headers", "Content-Type", "Authorization", "Access-Control-Allow-Origin",
    #               "Set-Cookie"],
)

# Public routes
app.include_router(auth.router, tags=["Authentication"])

# Secured routes
app.include_router(gmail_oauth.router, tags=["Gmail OAuth"])


#app.include_router(mailbox.router)
#app.include_router(user_settings.router)


@app.get("/test")
def test():
    return {"message": "Test route working!"}

@app.get("/set-test-cookie")
def set_test_cookie(request: Request,response: Response):

    origin = request.headers.get("origin", "")

    cookie_params = {
        "key": "session_token",
        "value":"this_is_a_test",
        "httponly": True,
        "secure": True,
        "samesite": "none",
        "max_age": 3600,
        #"domain": ".azronix.xyz",
        "path": "/"
    }

    if not IS_DEV:
        cookie_params["domain"] = ".azronix.xyz"

    # Only in development, and only for localhost:3000
    if IS_DEV and "localhost:3000" in origin:
        cookie_params["secure"] = False  # Allow HTTP (insecure)
        cookie_params["samesite"] = "lax"  # Prevent rejection by browsers
        #cookie_params.pop("domain", None)  # No domain for localhost

    response.set_cookie(**cookie_params)
    return {"message": "Test cookie set"}


app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, global_exception_handler)
