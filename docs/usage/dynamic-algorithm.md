You can specify which algorithm you would like to use to sign the JWT by using the **algorithm** parameter in **create_access_token()** or **create_refresh_token()**. Also you need to specify which algorithms you would like to permit when validating in protected endpoint by settings `decode_algorithms` which take a *sequence*. If the JWT doesn't have algorithm in `decode_algorithms` the token will be rejected.

**Source Code**: <a href="https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/dynamic_algorithm.py" target="_blank">https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/dynamic_algorithm.py</a>


Create a file `examples/dynamic_algorithm.py`:

```python
{!../examples/dynamic_algorithm.py!}
```

**Running the Server**

To run the server, execute the following command:
```bash
$ python examples/dynamic_algorithm.py
```
This will start the FastAPI server on http://127.0.0.1:8000/.