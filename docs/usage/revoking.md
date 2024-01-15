This will allow you to revoke a specific tokens so that it can no longer access your endpoints. You will have to choose
what tokens you want to check against the denylist. Denylist works by providing a callback function to this extension,
using the **token_in_denylist_loader()**. This method will be called whenever the specified tokens *(access and/or
refresh)* is used to access a protected endpoint. If the callback function says that the tokens is revoked, we will not
allow the requester to continue, otherwise we will allow the requester to access the endpoint as normal.

Here is a basic example use tokens revoking:

**Source Code**: <a href="https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/deny_list.py" target="_blank">https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/deny_list.py</a>

```python
{!../examples/deny_list.py!}
```
**Running the Server**

To run the server, execute the following command:
```bash
$ python examples/deny_list.py
```
This will start the FastAPI server on http://127.0.0.1:8000/.

In production, you will likely want to use either a database or in-memory store (such as Redis) to store your tokens.
Memory stores are great if you are wanting to revoke a tokens when the users log out and you can define timeout to your
tokens in Redis, after the timeout has expired, the tokens will automatically be deleted.



Here example use Redis for revoking a tokens:

**Source Code**: <a href="https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/deny_list_redis.py" target="_blank">https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/deny_list_redis.py</a>

!!! note
    Before that make sure redis already installed on your local machine,
    you can use docker using this command `docker run -d -p 6379:6379 redis`

```python
{!../examples/deny_list_redis.py!}
```
**Running the Server**

To run the server, execute the following command:
```bash
$ python examples/deny_list_redis.py
```
This will start the FastAPI server on http://127.0.0.1:8000/.