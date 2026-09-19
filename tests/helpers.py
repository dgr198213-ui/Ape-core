import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

from ape.classification import Endpoint, EndpointKind
from ape.router import LLMEndpoint


class MockLLM:
    """Servidor HTTP real en loopback que imita /chat/completions y sendMessage."""

    def __init__(self, reply="[]", status=200):
        self.requests: list[dict] = []
        self.reply = reply
        self.status = status
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(n)
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                if outer.status != 200:
                    self.send_response(outer.status)
                    self.end_headers()
                    return
                payload = json.dumps({"choices": [{"message": {"content": outer.reply}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def endpoint(name, kind, mock, reviewed=False, key="", model="m"):
    return LLMEndpoint(Endpoint(name, kind, reviewed), mock.base_url, model, key)


LOCAL, FREE = EndpointKind.LOCAL, EndpointKind.REMOTE_FREE


@contextmanager
def role(conn, name):
    conn.execute(f"set session authorization {name}")
    try:
        yield conn
    finally:
        conn.execute("reset session authorization")


def as_agent(conninfo):
    import psycopg
    conn = psycopg.connect(conninfo, autocommit=True)
    conn.execute("set session authorization ape_agent")
    conn.execute("set search_path = ape, extensions, public, pg_catalog")
    return conn


def propose_action(agent, tool="payment.execute", args=None, cost=20, hash_=None, origin="agent"):
    """Inserta una propuesta como ape_agent (como haría el ciclo). Devuelve el id."""
    import uuid
    from psycopg.types.json import Jsonb
    from ape.canon import args_hash
    args = args if args is not None else {"to": "proveedor", "eur": 20}
    return str(agent.execute(
        "insert into ape.action(tool, args, args_hash, cost_eur, origin, idempotency_key) "
        "values (%s, %s, %s, %s, %s, %s) returning id",
        (tool, Jsonb(args), hash_ or args_hash(args), cost, origin, uuid.uuid4().hex)).fetchone()[0])
