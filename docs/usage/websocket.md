The WebSocket protocol doesn’t handle authorization or authentication. Practically, this means that a WebSocket opened from a page behind auth doesn’t "automatically" receive any sort of auth. You need to take steps to also secure the WebSocket connection.

Since you cannot customize WebSocket headers from JavaScript, you’re limited to the "implicit" auth (i.e. Basic or cookies) that’s sent from the browser. The more common approach to generates a token from your normal HTTP server and then have the client send the token (either as a query string in the WebSocket path or as the first WebSocket message). The WebSocket server then validates that the token is valid.

Here is an example of how you authorize from query URL:

**Source Code**: <a href="https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/websocket.py" target="_blank">https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/websocket.py</a>

Create a file `examples/websocket.py`:

```python
{!../examples/websocket.py!}
```

**Running the Server**

To run the server, execute the following command:
```bash
$ python examples/websocket.py
```
This will start the FastAPI server on http://127.0.0.1:8000/.