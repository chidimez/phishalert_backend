from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware


from routers import auth, gmail_oauth
from fastapi import FastAPI
from utils.handlers import http_exception_handler, global_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException
from utils.handlers import http_exception_handler, global_exception_handler
from fastapi import FastAPI, HTTPException
from utils.handlers import http_exception_handler, global_exception_handler




app = FastAPI()

# CORS setup
origins = [
    "http://localhost:3000",  # local dev
    "https://phishalert.azronix.xyz",  # deployed site
    "*",  # Allows all origins (not recommended for production)
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # allow methods
    allow_headers=["*"], # allow headers
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

app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, global_exception_handler)