import importlib.util
import io
from pathlib import Path


PATH = Path(__file__).parents[1] / "llm_relay/app.py"
spec = importlib.util.spec_from_file_location("llm_relay", PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(module)


def test_relay_allowlists_only_inference_routes():
    assert module.path_allowed("/v1/responses")
    assert module.path_allowed("/v1/chat/completions?x=1")
    assert module.path_allowed("/v1/models")
    assert not module.path_allowed("/v1/files")
    assert not module.path_allowed("https://example.com/")


def test_oauth_relay_allowlists_only_required_hosts_and_paths():
    assert module.oauth_path_allowed("auth.openai.com", "/api/accounts/deviceauth/usercode")
    assert module.oauth_path_allowed("auth.openai.com", "/api/accounts/deviceauth/token")
    assert module.oauth_path_allowed("auth.openai.com", "/oauth/token")
    assert module.oauth_path_allowed("chatgpt.com", "/backend-api/codex/models?client_version=0.2.2")
    assert module.oauth_path_allowed("chatgpt.com", "/backend-api/codex/responses")
    assert not module.oauth_path_allowed("chatgpt.com", "/")
    assert not module.oauth_path_allowed("example.com", "/backend-api/codex/responses")


def test_oauth_relay_restricts_methods_per_route():
    assert module.oauth_request_allowed(
        "GET", "chatgpt.com", "/backend-api/codex/models?client_version=0.2.2"
    )
    assert not module.oauth_request_allowed("POST", "chatgpt.com", "/backend-api/codex/models")
    assert module.oauth_request_allowed("POST", "chatgpt.com", "/backend-api/codex/responses")
    assert not module.oauth_request_allowed("GET", "chatgpt.com", "/backend-api/codex/responses")
    assert module.oauth_request_allowed("POST", "auth.openai.com", "/oauth/token")
    assert not module.oauth_request_allowed("GET", "auth.openai.com", "/oauth/token")


def test_model_catalog_has_one_fixed_internal_route():
    assert module.catalog_path_allowed("/models/api.json")
    assert not module.catalog_path_allowed("/models/")
    assert not module.catalog_path_allowed("/models/anything-else")


class FakeResponse:
    status = 200

    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.read1_sizes = []

    def getheaders(self):
        return [("Content-Type", "text/event-stream"), ("Transfer-Encoding", "chunked")]

    def read1(self, size):
        self.read1_sizes.append(size)
        return next(self.chunks, b"")


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.closed = False

    def request(self, *args, **kwargs):
        return None

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def make_forward_handler(output):
    handler = object.__new__(module.BaseRelayHandler)
    handler.command = "POST"
    handler.path = "/backend-api/codex/responses"
    handler.headers = {"Authorization": "Bearer test"}
    handler.wfile = output
    handler.close_connection = False
    handler.send_response = lambda status: None
    handler.send_header = lambda name, value: None
    handler.end_headers = lambda: None
    handler.log_error = lambda *args: None
    return handler


def test_forward_streams_available_chunks_and_closes_downstream(monkeypatch):
    response = FakeResponse([b"data: one\n\n", b"data: two\n\n"])
    connection = FakeConnection(response)
    monkeypatch.setattr(module.http.client, "HTTPSConnection", lambda *args, **kwargs: connection)
    output = io.BytesIO()
    handler = make_forward_handler(output)

    handler.forward("chatgpt.com", b"{}")

    assert output.getvalue() == b"data: one\n\ndata: two\n\n"
    assert response.read1_sizes == [65536, 65536, 65536]
    assert handler.close_connection is True
    assert connection.closed is True


def test_forward_does_not_send_second_response_after_stream_started(monkeypatch):
    response = FakeResponse([b"data: one\n\n"])
    connection = FakeConnection(response)
    monkeypatch.setattr(module.http.client, "HTTPSConnection", lambda *args, **kwargs: connection)

    class BrokenOutput:
        closed = False

        def write(self, data):
            raise BrokenPipeError

        def flush(self):
            return None

    handler = make_forward_handler(BrokenOutput())
    error_responses = []
    handler.send_json = lambda *args: error_responses.append(args)

    handler.forward("chatgpt.com", b"{}")

    assert error_responses == []
    assert handler.close_connection is True
    assert connection.closed is True
