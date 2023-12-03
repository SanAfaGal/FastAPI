from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from routers import models, users, jwt_auth, auth

# Instance
app = FastAPI()

app.include_router(users.router)
app.include_router(models.router)
app.include_router(jwt_auth.router)
# app.include_router(auth.router)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Every call to server should be async
@app.get("/")
async def root():
    return {"message": "Hello"}


