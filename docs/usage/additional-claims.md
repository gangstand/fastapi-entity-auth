

You may want to store additional information in the access token or refresh token and you could later access in the protected views. This can be done easily by parsing additional information *(dictionary python)* to parameter **user_claims** in function **create_access_token()** or **create_refresh_token()**, and the data can be accessed later in a protected endpoint with the **get_raw_jwt()** function.

Storing data in the tokens can be good for performance. If you store data in the tokens, you won't need to look it up from disk next time you need it in a protected endpoint. However, you should take care of what data you put in the tokens. Any data in the tokens can be trivially viewed by anyone who can read the tokens.

**Note**: *Do not store sensitive information in the tokens!*

**Source Code**: <a href="https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/additional_claims.py" target="_blank">https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/additional_claims.py</a>

Create a file `examples/additional_claims.py`:

```python
{!../examples/additional_claims.py!}
```

**Running the Server**

To run the server, execute the following command:
```bash
$ python examples/basic.py
```
This will start the FastAPI server on http://127.0.0.1:8000/.