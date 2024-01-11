import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from fastapi_entity_auth import EntityAuth

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


# set deny_list enabled to True
# you can set to check access or refresh token or even both of them
class UtilsEntityAuth(EntityAuth):
    secret_key: str = "secret"
    deny_list_enabled: bool = True
    deny_list_token_checks: set = {"access", "refresh"}


instance_auth = UtilsEntityAuth

# A storage engine to save revoked tokens. in production,
# you can use Redis for storage system
deny_list = set()


# For this example, we are just checking if the tokens jti
# (unique identifier) is in the deny_list set. This could
# be made more complex, for example storing the token in Redis
# with the value true if revoked and false if not revoked
@instance_auth.token_in_deny_list_loader
def check_if_token_in_deny_list(decrypted_token: dict) -> bool:
    jti = decrypted_token["jti"]
    return jti in deny_list


@app.post("/login")
def login(data: User, authorize: instance_auth = Depends()) -> dict:
    if data.username != "string" or data.password != "string":
        raise HTTPException(status_code=401, detail="Bad username or password")

    access_token = authorize.create_access_token(subject=data.username)
    refresh_token = authorize.create_refresh_token(subject=data.username)
    return {"access_token": access_token, "refresh_token": refresh_token}


# Standard refresh endpoint. Token in deny_list will not
# be able to access this endpoint
@app.post("/refresh")
def refresh(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_refresh_token_required()

    current_user = authorize.get_jwt_subject()
    new_access_token = authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}


# Endpoint for revoking the current users access token
@app.delete("/access-revoke")
def access_revoke(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_required()

    jti = authorize.get_raw_jwt()["jti"]
    deny_list.add(jti)
    return {"detail": "Access token has been revoke"}


# Endpoint for revoking the current users refresh token
@app.delete("/refresh-revoke")
def refresh_revoke(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_refresh_token_required()

    jti = authorize.get_raw_jwt()["jti"]
    deny_list.add(jti)
    return {"detail": "Refresh token has been revoke"}


# A token in deny_list will not be able to access this any more
@app.get("/protected")
def protected(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_required()

    current_user = authorize.get_jwt_subject()
    return {"user": current_user}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
