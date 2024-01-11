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
    decode_algorithms: set = {"HS384", "HS512"}


instance_auth = UtilsEntityAuth


@app.post("/login")
def login(data: User, authorize: instance_auth = Depends()) -> dict:
    if data.username != "string" or data.password != "string":
        raise HTTPException(status_code=401, detail="Bad username or password")

    # You can define different algorithm when create a token
    access_token = authorize.create_access_token(subject=data.username, algorithm="HS384")
    refresh_token = authorize.create_refresh_token(subject=data.username, algorithm="HS512")
    return {"access_token": access_token, "refresh_token": refresh_token}


# In protected route, automatically check incoming JWT
# have algorithm in your `decode_algorithms` or not
@app.post("/refresh")
def refresh(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_refresh_token_required()

    current_user = authorize.get_jwt_subject()
    new_access_token = authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}


# In protected route, automatically check incoming JWT
# have algorithm in your `decode_algorithms` or not
@app.get("/protected")
def protected(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_required()

    current_user = authorize.get_jwt_subject()
    return {"user": current_user}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
