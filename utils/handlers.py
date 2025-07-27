from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
import traceback
import os

ENV = os.getenv("ENV", "production").lower()


async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )


async def global_exception_handler(request: Request, exc: Exception):
    if ENV == "development":
        return JSONResponse(
            status_code=500,
            content={
                "message": "Internal Server Error",
                "trace": traceback.format_exc(),
            },
        )
    return JSONResponse(
        status_code=500,
        content={"message": "Internal Server Error"},
    )


def json_response(data: dict, status_code: int = 200):
    return JSONResponse(content=data, status_code=status_code)