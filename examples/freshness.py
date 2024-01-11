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


# Standard login endpoint. Will return a fresh access token and a refresh token
@app.post("/login")
def login(data: User, authorize: instance_auth = Depends()) -> dict:
    if data.username != "string" or data.password != "string":
        raise HTTPException(status_code=401, detail="Bad username or password")

    """
    create_access_token supports an optional 'fresh' argument,
    which marks the token as fresh or non-fresh accordingly.
    As we just verified their username and password, we are
    going to mark the token as fresh here.
    """
    access_token = authorize.create_access_token(subject=data.username, fresh=True)
    refresh_token = authorize.create_refresh_token(subject=data.username)
    return {"access_token": access_token, "refresh_token": refresh_token}


@app.post("/refresh")
def refresh(authorize: instance_auth = Depends()) -> dict:
    """Refresh token endpoint. This will generate a new access token from
    the refresh token, but will mark that access token as non-fresh,
    as we do not actually verify a password in this endpoint.
    """
    authorize.jwt_refresh_token_required()

    current_user = authorize.get_jwt_subject()
    new_access_token = authorize.create_access_token(subject=current_user, fresh=False)
    return {"access_token": new_access_token}


@app.post("/fresh-login")
def fresh_login(data: User, authorize: instance_auth = Depends()) -> dict:
    """Fresh login endpoint. This is designed to be used if we need to
    make a fresh token for a user (by verifying they have the
    correct username and password). Unlike the standard login endpoint,
    this will only return a new access token, so that we don't keep
    generating new refresh tokens, which entirely defeats their point.
    """
    if data.username != "string" or data.password != "string":
        raise HTTPException(status_code=401, detail="Bad username or password")

    new_access_token = authorize.create_access_token(subject=data.username, fresh=True)
    return {"access_token": new_access_token}


# Any valid JWT access token can access this endpoint
@app.get("/protected")
def protected(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_required()

    current_user = authorize.get_jwt_subject()
    return {"user": current_user}


# Only fresh JWT access token can access this endpoint
@app.get("/protected-fresh")
def protected_fresh(authorize: instance_auth = Depends()) -> dict:
    authorize.fresh_jwt_required()

    current_user = authorize.get_jwt_subject()
    return {"user": current_user}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
