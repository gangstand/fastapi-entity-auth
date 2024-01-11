import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from starlette.websockets import WebSocketDisconnect

from fastapi_entity_auth import EntityAuth

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


class UtilsEntityAuth(EntityAuth):
    secret_key: str = "secret"


instance_auth = UtilsEntityAuth


class WebSocketManager:
    def __init__(self) -> None:
        self.websocket_connections = set()

    def add_connection(self, websocket: WebSocket) -> None:
        self.websocket_connections.add(websocket)

    def remove_connection(self, websocket: WebSocket) -> None:
        self.websocket_connections.remove(websocket)

    async def broadcast(self, message: str) -> None:
        for connection in self.websocket_connections:
            await connection.send_text(str(message))


websocket_manager = WebSocketManager()

html = """
<!DOCTYPE html>
<html>
    <head>
        <title>authorize</title>
    </head>
    <body>
        <h1>WebSocket authorize</h1>
        <p>Token:</p>
        <textarea id="token" rows="4" cols="50"></textarea><br><br>
        <button onclick="websocketfun()">Send</button>
        <ul id='messages'>
        </ul>
        <script>
            const websocketfun = () => {
                let token = document.getElementById("token").value
                let ws = new WebSocket(`ws://localhost:8000/ws?token=${token}`)
                ws.onmessage = (event) => {
                    let messages = document.getElementById('messages')
                    let message = document.createElement('li')
                    let content = document.createTextNode(event.data)
                    message.appendChild(content)
                    messages.appendChild(message)
                }
            }
        </script>
    </body>
</html>
"""


@app.get("/")
async def get() -> HTMLResponse:
    return HTMLResponse(html)


@app.websocket("/ws")
async def websocket_endpoint(
        websocket: WebSocket,
        token: str = Query(...),
        auth: instance_auth = Depends()) -> None:
    await websocket.accept()
    try:
        websocket_manager.add_connection(websocket)
        auth.jwt_required(auth_from="websocket", token=token)
        await websocket.send_text(str({"detail": "Successfully Login"}))

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        websocket_manager.remove_connection(websocket)
    except Exception:
        websocket_manager.remove_connection(websocket)
        await websocket.close()


@app.post("/login")
def login(data: User, authorize: instance_auth = Depends()) -> dict:
    if data.username != "string" or data.password != "string":
        raise HTTPException(status_code=401, detail="Bad username or password")
    access_token = authorize.create_access_token(subject=data.username, fresh=True)
    refresh_token = authorize.create_refresh_token(subject=data.username)
    return {"access_token": access_token, "refresh_token": refresh_token}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
