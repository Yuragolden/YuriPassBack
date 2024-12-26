import aioredis

REDIS_URL = "redis://localhost:6379"
redis = aioredis.from_url(REDIS_URL, decode_responses=True)
