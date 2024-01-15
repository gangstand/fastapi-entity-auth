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


@app.post('/refresh')
def refresh(authorize: instance_auth = Depends()):
    """
    The jwt_refresh_token_required() function insures a valid refresh
    token is present in the request before running any code below that function.
    we can use the get_jwt_subject() function to get the subject of the refresh
    token, and use the create_access_token() function again to make a new access token
    """
    authorize.jwt_refresh_token_required()

    current_user = authorize.get_jwt_subject()
    new_access_token = authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}


@app.get('/protected')
def protected(authorize: instance_auth = Depends()):
    authorize.jwt_required()

    current_user = authorize.get_jwt_subject()
    return {"user": current_user}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
