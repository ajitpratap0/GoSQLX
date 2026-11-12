"""Binding ownership and decoder contracts; fake-library tests never skip."""
import ctypes
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from pygosqlx import core
from pygosqlx.exceptions import GoSQLXError


class FakeFunction:
    def __init__(self, call):
        self.call = call
        self.calls = []
        self.configurations = []

    def __setattr__(self, name, value):
        if name in ('argtypes', 'restype'):
            self.configurations.append(name)
        object.__setattr__(self, name, value)

    def __call__(self, *args):
        self.calls.append(args)
        return self.call(*args)


class FakeLibrary:
    def __init__(self, raw=b'{"success":true,"statement_count":1,"statement_types":["SELECT"],"valid":true,"tables":["t"]}', old=False):
        self.raw = raw
        self.buffers = []
        self.freed = []
        self.lookups = {}
        names = {'gosqlx_parse', 'gosqlx_validate', 'gosqlx_extract_tables', 'gosqlx_free', 'gosqlx_version'}
        if not old:
            names |= set(core._DIALECT_EXPORTS) | set(core._DIALECT_EXPORTS.values()) | {'gosqlx_lint', 'gosqlx_security_scan', 'gosqlx_transpile', 'gosqlx_dialects'}
        self.functions = {name: FakeFunction(self.allocate) for name in names}
        self.functions['gosqlx_free'] = FakeFunction(self.freed.append)
        self.functions['gosqlx_version'] = FakeFunction(lambda: self.allocate(raw=b'1.2.3'))

    def allocate(self, *args, raw=None):
        payload = self.raw if raw is None else raw
        if payload is None:
            return None
        buf = ctypes.create_string_buffer(payload)
        self.buffers.append(buf)
        return ctypes.addressof(buf)

    def __getattr__(self, name):
        self.lookups[name] = self.lookups.get(name, 0) + 1
        try:
            return self.functions[name]
        except KeyError:
            raise AttributeError(name) from None


def use_fake(monkeypatch, fake):
    monkeypatch.setattr(core, '_bindings', None, raising=False)
    monkeypatch.setattr(core, '_get_lib_path', lambda: 'fake')
    monkeypatch.setattr(core.ctypes, 'CDLL', lambda path: fake)


def test_resolve_and_configure_once(monkeypatch):
    fake = FakeLibrary()
    use_fake(monkeypatch, fake)
    for _ in range(10):
        assert core.parse('SELECT 1').statement_count == 1
        assert core.parse('SELECT 1', dialect='mysql').statement_count == 1
    assert set(fake.lookups.values()) == {1}
    for name, fn in fake.functions.items():
        assert fn.configurations == ['argtypes', 'restype']
        assert fn.restype is (None if name == 'gosqlx_free' else ctypes.c_void_p)
    assert len(fake.freed) == 20
    assert core._get_lib() is fake


def test_old_library_defaults_and_missing_exports(monkeypatch):
    fake = FakeLibrary(old=True)
    use_fake(monkeypatch, fake)
    assert core.parse('SELECT 1').statement_count == 1
    assert core.validate('SELECT 1')
    assert core.extract_tables('SELECT a FROM t') == ['t']
    for name, call in [('gosqlx_parse_dialect', lambda: core.parse('SELECT 1', dialect='mysql')), ('gosqlx_lint', lambda: core.lint('SELECT 1'))]:
        with pytest.raises(GoSQLXError) as err:
            call()
        assert str(err.value) == f'{name} not available in this library build. Rebuild the shared library with the latest cbinding.'
    assert set(fake.lookups.values()) == {1}


@pytest.mark.parametrize('raw', [None, b'{broken', b'\xff', b'{"success":true}'])
def test_free_once_including_decode_failure(monkeypatch, raw):
    fake = FakeLibrary(raw=raw)
    use_fake(monkeypatch, fake)
    if raw is None:
        with pytest.raises(GoSQLXError, match='returned NULL'):
            core.parse('SELECT 1')
        assert fake.freed == []
    elif raw != b'{"success":true}':
        with pytest.raises(ValueError):
            core.parse('SELECT 1')
        assert len(fake.freed) == 1
    else:
        core.parse('SELECT 1')
        assert len(fake.freed) == 1


def test_copy_failure_frees_once(monkeypatch):
    fake = FakeLibrary()
    use_fake(monkeypatch, fake)
    def fail(pointer):
        raise RuntimeError('copy failed')
    monkeypatch.setattr(core.ctypes, 'string_at', fail)
    with pytest.raises(RuntimeError, match='copy failed'):
        core.parse('SELECT 1')
    assert len(fake.freed) == 1


def test_free_uses_origin_even_if_bindings_replaced(monkeypatch):
    first, second = FakeLibrary(), FakeLibrary()
    use_fake(monkeypatch, first)
    core.parse('SELECT 1')
    old = core._bindings
    use_fake(monkeypatch, second)
    core.parse('SELECT 1')
    current = core._bindings
    def replace_and_allocate(*args):
        monkeypatch.setattr(core, '_bindings', current)
        return first.allocate(*args)
    first.functions['gosqlx_parse'].call = replace_and_allocate
    monkeypatch.setattr(core, '_bindings', old)
    core.parse('SELECT 1')
    core.parse('SELECT 1')
    assert len(first.freed) == 2
    assert len(second.freed) == 2


def test_concurrent_first_calls_initialize_once(monkeypatch):
    fake = FakeLibrary()
    use_fake(monkeypatch, fake)
    barrier = threading.Barrier(16)
    loads = []
    def load(path):
        loads.append(path)
        return fake
    monkeypatch.setattr(core.ctypes, 'CDLL', load)
    def run(_):
        barrier.wait()
        return core.parse('SELECT 1').statement_count
    with ThreadPoolExecutor(max_workers=16) as pool:
        assert list(pool.map(run, range(16))) == [1] * 16
    assert loads == ['fake']


def test_version_and_null(monkeypatch):
    fake = FakeLibrary()
    use_fake(monkeypatch, fake)
    assert core.version() == '1.2.3'
    assert len(fake.freed) == 1
    fake.functions['gosqlx_version'].call = lambda: None
    with pytest.raises(GoSQLXError, match='gosqlx_version returned NULL'):
        core.version()
    assert len(fake.freed) == 1


@pytest.mark.parametrize('force_stdlib', [True, False])
def test_decoder_import_selection_in_subprocess(force_stdlib):
    script = '''
import sys, json
if FORCE_STDLIB:
    sys.modules['orjson'] = None
from pygosqlx import core
assert core._DECODER == EXPECTED
raw = '{"text":"café ✓ 日本"}'.encode()
assert core._loads(raw) == json.loads(raw)
for raw in [b'{broken', b'\\xff']:
    try:
        core._loads(raw)
    except ValueError:
        pass
    else:
        raise AssertionError('malformed response accepted')
'''
    expected = 'json' if force_stdlib or importlib.util.find_spec('orjson') is None else 'orjson'
    script = script.replace('FORCE_STDLIB', repr(force_stdlib)).replace('EXPECTED', repr(expected))
    subprocess.run([sys.executable, '-c', script], check=True, cwd=Path(__file__).resolve().parents[1])


def _reference_call_and_decode(bindings, func, *args):
    """Frozen pre-change call/copy/UTF-8/stdlib decode/free sequence."""
    result_ptr = func(*args)
    if result_ptr is None:
        raise GoSQLXError('C function returned NULL — possible out-of-memory')
    try:
        raw = ctypes.string_at(result_ptr)
        # Compare every native JSON response, including errors and Unicode.
        if importlib.util.find_spec('orjson') is not None:
            import orjson
            assert orjson.loads(raw) == json.loads(raw)
        return json.loads(raw.decode('utf-8'))
    finally:
        bindings.lib.gosqlx_free(result_ptr)


def _run_differential():
    """Exercise every public operation with a real shared library, never skip."""
    from benchmarks.bench_core import QUERIES
    core._get_lib()  # fail explicitly if integration was not provisioned
    queries = list(QUERIES.values()) + ['SELECT * FROM', "SELECT 'café ✓ 日本' AS x"]
    original = core._call_and_decode
    operations = [core.parse, core.validate, core.validate_detailed, core.format,
                  core.extract_tables, core.extract_columns, core.extract_functions,
                  core.extract_metadata, core.lint, core.security_scan]
    def outcome(call):
        try:
            return ('result', call())
        except GoSQLXError as exc:
            return ('error', type(exc), str(exc), exc.__dict__)
    def compare(call):
        actual = outcome(call)
        core._call_and_decode = _reference_call_and_decode
        try:
            expected = outcome(call)
        finally:
            core._call_and_decode = original
        assert actual == expected
    compare(core.dialects)
    lib = core._get_lib()
    ptr = lib.gosqlx_version()
    try:
        expected_version = ctypes.string_at(ptr).decode('utf-8')
    finally:
        lib.gosqlx_free(ptr)
    assert core.version() == expected_version
    for sql in queries:
        for op in operations:
            compare(lambda op=op, sql=sql: op(sql))
        for dialect in core.dialects():
            for op in operations[:-1]:
                compare(lambda op=op, sql=sql, dialect=dialect: op(sql, dialect=dialect))
            compare(lambda sql=sql, dialect=dialect: core.transpile(sql, dialect, 'postgresql'))
    compare(lambda: core.lint('select café from t', max_line_length=10))
    compare(lambda: core.parse('SELECT 1', dialect='invalid'))


@pytest.mark.parametrize('force_stdlib', [True, False])
def test_real_library_differential_subprocess(force_stdlib):
    script = f'''
import sys
if {force_stdlib!r}:
    sys.modules['orjson'] = None
from tests.test_cached_bindings import _run_differential
_run_differential()
'''
    subprocess.run([sys.executable, '-c', script], check=True, cwd=Path(__file__).resolve().parents[1])


def test_decoder_runtime_failure_propagates_after_free(monkeypatch):
    fake = FakeLibrary()
    use_fake(monkeypatch, fake)
    def failing_decoder(raw):
        assert isinstance(raw, bytes)
        assert len(fake.freed) == 1
        raise RuntimeError('decoder failed')
    monkeypatch.setattr(core, '_loads', failing_decoder)
    with pytest.raises(RuntimeError, match='decoder failed'):
        core.parse('SELECT 1')
    assert fake.freed == [ctypes.addressof(fake.buffers[0])]


def test_binding_set_is_immutable(monkeypatch):
    from dataclasses import FrozenInstanceError
    fake = FakeLibrary()
    use_fake(monkeypatch, fake)
    core.parse('SELECT 1')
    with pytest.raises(FrozenInstanceError):
        core._bindings.free = lambda pointer: None


def test_import_is_lazy_and_does_not_mask_backend_runtime_failure():
    script = '''
import ctypes
ctypes.CDLL = lambda path: (_ for _ in ()).throw(AssertionError('eager load'))
from pygosqlx import core
assert core._bindings is None
'''
    subprocess.run([sys.executable, '-c', script], check=True, cwd=Path(__file__).resolve().parents[1])
    script = '''
import sys, types
class BrokenBackend(types.ModuleType):
    def __getattr__(self, name):
        if name == 'loads':
            raise RuntimeError('backend broken')
        raise AttributeError(name)
sys.modules['orjson'] = BrokenBackend('orjson')
try:
    from pygosqlx import core
except RuntimeError as exc:
    assert str(exc) == 'backend broken'
else:
    raise AssertionError('runtime failure masked')
'''
    subprocess.run([sys.executable, '-c', script], check=True, cwd=Path(__file__).resolve().parents[1])


@pytest.mark.parametrize('dialect', [None, 'mysql', ''])
@pytest.mark.parametrize('operation,export', [
    (core.parse, 'gosqlx_parse'),
    (core.validate, 'gosqlx_validate'),
    (core.validate_detailed, 'gosqlx_validate'),
    (core.format, 'gosqlx_format'),
    (core.extract_tables, 'gosqlx_extract_tables'),
    (core.extract_columns, 'gosqlx_extract_columns'),
    (core.extract_functions, 'gosqlx_extract_functions'),
    (core.extract_metadata, 'gosqlx_extract_metadata'),
])
def test_dispatch_uses_correct_export_and_arguments(monkeypatch, operation, export, dialect):
    fake = FakeLibrary()
    use_fake(monkeypatch, fake)
    sql = "SELECT 'café ✓ 日本' AS x"
    operation(sql, dialect=dialect)
    expected_export = export if dialect is None else export + '_dialect'
    expected_args = (sql.encode('utf-8'),)
    if dialect is not None:
        expected_args += (dialect.encode('utf-8'),)
    for name, function in fake.functions.items():
        if name == 'gosqlx_free':
            assert len(function.calls) == 1
        else:
            assert function.calls == ([expected_args] if name == expected_export else [])


def test_analysis_dispatch_and_lint_stdlib_serialization(monkeypatch):
    fake = FakeLibrary()
    use_fake(monkeypatch, fake)
    sql = "SELECT 'café ✓ 日本' AS x"
    raw = sql.encode('utf-8')
    core.lint(sql, dialect='mysql', max_line_length=40)
    assert fake.functions['gosqlx_lint'].calls == [
        (raw, json.dumps({'dialect': 'mysql', 'max_line_length': 40}).encode('utf-8'))
    ]
    core.security_scan(sql)
    assert fake.functions['gosqlx_security_scan'].calls == [(raw,)]
    core.transpile(sql, 'mysql', 'postgresql')
    assert fake.functions['gosqlx_transpile'].calls == [(raw, b'mysql', b'postgresql')]
    core.dialects()
    assert fake.functions['gosqlx_dialects'].calls == [()]
    assert len(fake.freed) == 4
