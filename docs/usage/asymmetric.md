Usage of RSA `RS*` and EC `EC*` algorithms require a basic understanding of how public-key cryptography is used with regards to digital signatures. If you are familiar with that, you may want to use this.

**Source Code**: <a href="https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/asymmetric.py" target="_blank">https://github.com/gangstand/fastapi-entity-auth/blob/main/examples/asymmetric.py</a>

Create a file `examples/asymmetric.py`:

```python
{!../examples/asymmetric.py!}
```
**Running the Server**

To run the server, execute the following command:
```bash
$ python examples/basic.py
```
This will start the FastAPI server on http://127.0.0.1:8000/.