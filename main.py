from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware


from routers import auth, gmail_oauth

app = FastAPI()

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # or ["*"] during dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Public routes
app.include_router(auth.router, tags=["Authentication"])

# Secured routes
app.include_router(gmail_oauth.router, tags=["Gmail OAuth"])
#app.include_router(mailbox.router)
#app.include_router(user_settings.router)


# Define the base endpoint
@app.get("/api/", description="Base endpoint.", tags=["Base"])
async def root() -> str:
    return "API is running. Navigate to /docs for the GUI."