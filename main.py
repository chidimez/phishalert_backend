from dotenv import load_dotenv

load_dotenv()
from starlette import FastAPI
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


