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

    # You can be passing custom claim to argument user_claims
    # in function create_access_token() or create refresh token()
    another_claims = {"role": ["User", "Admin"]}
    access_token = authorize.create_access_token(subject=data.username, user_claims=another_claims)
    return {"access_token": access_token}


# In protected route, get the claims you added to the jwt with the
# get_raw_jwt() method
@app.get("/claims")
def user(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_required()
    return authorize.get_raw_jwt()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
