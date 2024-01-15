import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from fastapi_entity_auth import EntityAuth

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


class UtilsEntityAuth(EntityAuth):
    secret_key: str = "secret"


instance_auth = UtilsEntityAuth


@app.post("/login")
def login(data: User, authorize: instance_auth = Depends()) -> dict:
    if data.username != "string" or data.password != "string":
        raise HTTPException(status_code=401, detail="Bad username or password")
    access_token = authorize.create_access_token(subject=data.username)
    return {"access_token": access_token}


@app.get("/partially-protected")
def partially_protected(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_optional()
    current_user = authorize.get_jwt_subject() or "anonymous"
    return {"user": current_user}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
