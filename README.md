<h1 align="left" style="margin-bottom: 20px; font-weight: 500; font-size: 50px; color: black;">
    FastAPI Entity Auth
</h1>

---

**Source Code**: <a href="https://github.com/gangstand/fastapi-entity-auth" target="_blank">https://github.com/gangstand/fastapi-entity-auth</a>

**Documentation**: <a href="https://gangstand.github.io/fastapi-entity-auth/" target="_blank">https://gangstand.github.io/fastapi-entity-auth/</a>

---

## Features

A FastAPI extension that provides support for JWT authentication (secure, easy to use, and lightweight).

- Access tokens and refresh tokens
- Freshness Tokens
- Revoking Tokens
- Support for WebSocket authorization
- Support for adding custom claims to JSON Web Tokens
- Storing tokens in cookies and CSRF protection

## Installation
The easiest way to start working with this extension with pip

```bash
pip install fastapi-entity-auth
```

If you want to use asymmetric (public/private) key signing algorithms, include the <b>cryptography</b> extra requirements.
```bash
pip install cryptography
```

## License

This project is licensed under the terms of the MIT license.