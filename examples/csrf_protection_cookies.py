import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

from fastapi_entity_auth import EntityAuth

"""
By default, the CRSF cookies will be called csrf_access_token and
csrf_refresh_token, and in protected endpoints we will look
for the CSRF token in the 'X-CSRF-Token' headers. only certain
methods should define CSRF token in headers default is ('POST','PUT','PATCH','DELETE')
"""

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class User(BaseModel):
    username: str
    password: str


class UtilsEntityAuth(EntityAuth):
    secret_key: str = "secret"
    # Configure application to store and get JWT from cookies
    token_location: set = {"cookies"}
    # Only allow JWT cookies to be sent over https
    cookie_secure: bool = False
    # Enable csrf double submit protection. default is True
    cookie_csrf_protect: bool = True
    # Change to 'lax' in production to make your website more secure from CSRF Attacks, default is None


instance_auth = UtilsEntityAuth


@app.post("/login")
def login(data: User, authorize: instance_auth = Depends()) -> dict:
    """With authjwt_cookie_csrf_protect set to True, set_access_cookies() and
    set_refresh_cookies() will now also set the non-httponly CSRF cookies.
    """
    if data.username != "string" or data.password != "string":
        raise HTTPException(status_code=401, detail="Bad username or password")

    # Create the tokens and passing to set_access_cookies or set_refresh_cookies
    access_token = authorize.create_access_token(subject=data.username)
    refresh_token = authorize.create_refresh_token(subject=data.username)

    # Set the JWT and CSRF double submit cookies in the response
    authorize.set_access_cookies(access_token)
    authorize.set_refresh_cookies(refresh_token)

    return {"access": access_token, "refresh": refresh_token}


@app.post("/refresh")
def refresh(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_refresh_token_required()

    current_user = authorize.get_jwt_subject()
    new_access_token = authorize.create_access_token(subject=current_user)
    # Set the JWT and CSRF double submit cookies in the response
    authorize.set_access_cookies(new_access_token)
    return {"msg": "The token has been refresh"}


@app.delete("/logout")
def logout(authorize: instance_auth = Depends()) -> dict:
    """Because the JWT are stored in an httponly cookie now, we cannot
    log the user out by simply deleting the cookie in the frontend.
    We need the backend to send us a response to delete the cookies.
    """
    authorize.jwt_required()

    authorize.unset_jwt_cookies()
    return {"msg": "Successfully logout"}


@app.get("/protected")
def protected(authorize: instance_auth = Depends()) -> dict:
    authorize.jwt_required()

    current_user = authorize.get_jwt_subject()
    return {"user": current_user}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
