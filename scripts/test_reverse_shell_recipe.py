"""Exercise optional MCP defaults using stub sockets; never open a listener."""
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1]/'mcp-servers/reverse_shell/mcp_reverse_shell.py'

class FastMCPFixture:
    def __init__(self, **kwargs): pass
    def tool(self, **kwargs): return lambda function: function

class ReverseShellBindTest(unittest.TestCase):
    def setUp(self):
        fixture = types.ModuleType('mcp.server.fastmcp')
        fixture.FastMCP = FastMCPFixture
        with mock.patch.dict(sys.modules, {'mcp': types.ModuleType('mcp'), 'mcp.server': types.ModuleType('mcp.server'), 'mcp.server.fastmcp': fixture}):
            spec = importlib.util.spec_from_file_location('reverse_shell_fixture', SCRIPT)
            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)
        self.bound = []
        owner = self
        class SocketFixture:
            def setsockopt(self, *args): pass
            def bind(self, address): owner.bound.append(address)
            def listen(self, *args): pass
            def settimeout(self, *args): pass
            def accept(self): return SocketFixture(), ('192.0.2.9', 1234)
            def close(self): pass
        class InlineThread:
            def __init__(self, target, args, **kwargs): self.target=target; self.args=args
            def start(self): self.target(*self.args)
            def is_alive(self): return False
            def join(self, **kwargs): pass
        for patch in [mock.patch.object(self.module.socket, 'socket', return_value=SocketFixture()),
                      mock.patch.object(self.module.threading, 'Thread', InlineThread),
                      mock.patch.object(self.module, '_get_local_ips', return_value=['192.0.2.7'])]:
            patch.start(); self.addCleanup(patch.stop)
        self.addCleanup(self.module._stop_listener)
    def test_existing_port_only_call_binds_loopback(self):
        with mock.patch.dict(self.module.os.environ, {}, clear=True):
            self.module.reverse_shell_start_listener(4444)
        self.assertEqual(self.bound, [('127.0.0.1', 4444)])
    def test_explicit_operator_interface_and_wildcard_remain_supported(self):
        with mock.patch.dict(self.module.os.environ, {'REVERSE_SHELL_ALLOW_NON_LOOPBACK':'true'}, clear=True):
            self.module.reverse_shell_start_listener(4444, '0.0.0.0')
            self.module.reverse_shell_start_listener(4445, '192.0.2.7')
        self.assertEqual(self.bound, [('0.0.0.0', 4444), ('192.0.2.7', 4445)])
    def test_model_argument_cannot_opt_in_to_network_exposure(self):
        with mock.patch.dict(self.module.os.environ, {}, clear=True):
            for host in ['0.0.0.0', '192.0.2.7']:
                self.assertIn('requires operator opt-in', self.module.reverse_shell_start_listener(4444, host))
        self.assertEqual(self.bound, [])
    def test_configured_interface_and_invalid_input(self):
        with mock.patch.dict(self.module.os.environ, {'REVERSE_SHELL_BIND_HOST':'192.0.2.8', 'REVERSE_SHELL_ALLOW_NON_LOOPBACK':'true'}, clear=True):
            self.module.reverse_shell_start_listener(4444)
        self.assertEqual(self.bound, [('192.0.2.8', 4444)])
        result = self.module.reverse_shell_start_listener(4444, 'host.invalid; widen scope')
        self.assertIn('must be an IPv4', result)
        self.assertEqual(len(self.bound), 1)

if __name__ == '__main__': unittest.main()
