The fresh tokens pattern is built into this extension. This pattern is very simple, you can choose to mark some access tokens as fresh and other as a non-fresh tokens, and use the **fresh_jwt_required()** function to only allow fresh tokens to access the certain endpoint.

This is useful for allowing the fresh tokens to do some critical things (such as update information user) in real case you can see in the GitHub system when user wants to delete a repository in a certain time you need login if tokens not fresh again. Utilizing Fresh tokens in conjunction with refresh tokens can lead to a more secure site, without creating a bad user experience by making users constantly re-authenticate.

Here is an example of how you could utilize refresh tokens with the fresh token pattern:

**Source Code**: <a href="https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/freshness.py" target="_blank">https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/freshness.py</a>

Create a file examples/freshness.py:

```python
{!../examples/freshness.py!}
```
**Running the Server**

To run the server, execute the following command:
```bash
$ python examples/freshness.py
```
This will start the FastAPI server on http://127.0.0.1:8000/.