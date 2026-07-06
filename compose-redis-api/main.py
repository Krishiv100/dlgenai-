import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import redis.asyncio as redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)


@app.get("/")
async def root():
    return {
        "message": "FastAPI Redis counter service is running",
        "endpoints": ["/healthz", "/hit/{key}", "/count/{key}"]
    }


@app.get("/healthz")
async def healthz():
    try:
        pong = await r.ping()
        if pong:
            return {"status": "ok", "redis": "up"}
    except Exception:
        pass

    raise HTTPException(
        status_code=503,
        detail={"status": "error", "redis": "down"}
    )


@app.post("/hit/{key}")
async def hit_key(key: str):
    redis_key = f"counter:{key}"

    # Redis INCR is atomic
    count = await r.incr(redis_key)

    return {
        "key": key,
        "count": count
    }


@app.get("/count/{key}")
async def get_count(key: str):
    redis_key = f"counter:{key}"

    value = await r.get(redis_key)

    if value is None:
        count = 0
    else:
        count = int(value)

    return {
        "key": key,
        "count": count
    }