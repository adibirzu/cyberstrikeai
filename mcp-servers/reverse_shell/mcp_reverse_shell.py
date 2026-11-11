#!/usr/bin/env python3
"""Optional reverse-shell MCP server for an authorized operator.
Starts/stops one TCP listener and exchanges commands with one connected client.
Requires mcp. Configure it explicitly as a stdio MCP server; it is not enabled
by importing the CyberStrikeAI application and it is not an execution sandbox.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import threading
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# 反向 Shell 状态（单例：一个监听器、一个已连接客户端）
# ---------------------------------------------------------------------------

_LISTENER: socket.socket | None = None
_LISTENER_THREAD: threading.Thread | None = None
_LISTENER_PORT: int | None = None
_LISTENER_HOST: str | None = None
_CLIENT_SOCK: socket.socket | None = None
_CLIENT_ADDR: tuple[str, int] | None = None
_LOCK = threading.Lock()
_STOP_EVENT = threading.Event()
_READY_EVENT = threading.Event()
_LAST_LISTEN_ERROR: str | None = None
_LISTENER_THREAD_JOIN_TIMEOUT = 1.0
_START_READY_TIMEOUT = 1.5

# 用于 send_command 的输出结束标记（避免无限等待）
_END_MARKER = "__RS_DONE__"
_RECV_TIMEOUT = 30.0
_RECV_CHUNK = 4096


def _get_local_ips() -> list[str]:
    'Get local callback-address candidates, preferring non-loopback addresses.'
    ips: list[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != "127.0.0.1":
            ips.append(ip)
    except OSError:
        pass
    if not ips:
        try:
            ip = socket.gethostbyname(socket.gethostname())
            if ip:
                ips.append(ip)
        except OSError:
            pass
    if not ips:
        ips.append("127.0.0.1")
    return ips


def _accept_loop(port: int, bind_host: str) -> None:
    'Bind/listen/accept in a background thread; accept one client.'
    global _LISTENER, _CLIENT_SOCK, _CLIENT_ADDR, _LISTENER_PORT, _LISTENER_HOST, _LAST_LISTEN_ERROR
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_host, port))
        sock.listen(1)
        # 避免 stop_listener 关闭后 accept() 长时间不返回：用超时轮询检查停止事件
        sock.settimeout(0.5)
        with _LOCK:
            _LISTENER = sock
            _LISTENER_PORT = port
            _LISTENER_HOST = bind_host
            _LAST_LISTEN_ERROR = None
            _READY_EVENT.set()
        # 循环 accept：只接受一个连接，或等待 stop 事件
        while not _STOP_EVENT.is_set():
            try:
                client, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with _LOCK:
                _CLIENT_SOCK = client
                _CLIENT_ADDR = (addr[0], addr[1])
            break
    except OSError as e:
        with _LOCK:
            _LAST_LISTEN_ERROR = str(e)
            _READY_EVENT.set()
    finally:
        with _LOCK:
            _LISTENER = None
            _LISTENER_PORT = None
            _LISTENER_HOST = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _start_listener(port: int, bind_host: str = "127.0.0.1") -> str:
    global _LISTENER_THREAD, _LISTENER_PORT, _CLIENT_SOCK, _CLIENT_ADDR, _LAST_LISTEN_ERROR
    old_thread: threading.Thread | None = None
    with _LOCK:
        if _LISTENER is not None:
            # _LISTENER_PORT 可能短暂为 None（例如刚 stop/start），因此做个兜底显示
            show_port = _LISTENER_PORT if _LISTENER_PORT is not None else port
            return f"Already listening on port {show_port}. Stop the listener before starting another."
        if _CLIENT_SOCK is not None:
            try:
                _CLIENT_SOCK.close()
            except OSError:
                pass
            _CLIENT_SOCK = None
            _CLIENT_ADDR = None
        old_thread = _LISTENER_THREAD

    # 若旧线程还没完全退出，短暂等待一下以减少端口绑定失败概率
    if old_thread is not None and old_thread.is_alive():
        old_thread.join(timeout=0.5)

    _STOP_EVENT.clear()
    _READY_EVENT.clear()
    _LAST_LISTEN_ERROR = None
    th = threading.Thread(target=_accept_loop, args=(port, bind_host), daemon=True)
    th.start()
    _LISTENER_THREAD = th

    # 等待后台线程完成 bind/listen（或失败）
    _READY_EVENT.wait(timeout=_START_READY_TIMEOUT)
    with _LOCK:
        err = _LAST_LISTEN_ERROR
        listening = _LISTENER is not None

    if listening:
        ips = _get_local_ips() if bind_host == "0.0.0.0" else [bind_host]
        addrs = ", ".join(f"{ip}:{port}" for ip in ips)
        return (
            f"Listening on {bind_host}:{port}. Plaintext and unauthenticated; restrict the network. "
            f"Authorized target callback addresses: {addrs}. After connection, use reverse_shell_send_command for scoped commands."
        )

    if err:
        return f"Failed to listen on {bind_host}:{port}: {err}"

    # 仍未准备好：可能线程调度较慢或环境异常；给出可操作的提示
    return f"Listener on {bind_host}:{port} is not ready. Check reverse_shell_status or retry later."


def _stop_listener() -> str:
    global _LISTENER, _LISTENER_THREAD, _CLIENT_SOCK, _CLIENT_ADDR, _LISTENER_PORT, _LISTENER_HOST
    listener_sock: socket.socket | None = None
    client_sock: socket.socket | None = None
    old_thread: threading.Thread | None = None
    with _LOCK:
        _STOP_EVENT.set()
        _READY_EVENT.set()
        listener_sock = _LISTENER
        old_thread = _LISTENER_THREAD
        _LISTENER = None
        _LISTENER_PORT = None
        _LISTENER_HOST = None
        client_sock = _CLIENT_SOCK
        _CLIENT_SOCK = None
        _CLIENT_ADDR = None

    if listener_sock is not None:
        try:
            listener_sock.close()
        except OSError:
            pass
    if client_sock is not None:
        try:
            client_sock.close()
        except OSError:
            pass

    # 等待监听线程退出，避免 stop/start 竞态导致“端口 None 仍提示已在监听中”
    if old_thread is not None and old_thread.is_alive():
        old_thread.join(timeout=_LISTENER_THREAD_JOIN_TIMEOUT)
    with _LOCK:
        _LISTENER_THREAD = None
    return 'Listener stopped; the current client, if any, was disconnected.'


def _disconnect_client() -> str:
    global _CLIENT_SOCK, _CLIENT_ADDR
    with _LOCK:
        if _CLIENT_SOCK is None:
            return 'No client currently connected.'
        try:
            _CLIENT_SOCK.close()
        except OSError:
            pass
        addr = _CLIENT_ADDR
        _CLIENT_SOCK = None
        _CLIENT_ADDR = None
    return f"Disconnected client {addr}."


def _status() -> dict[str, Any]:
    with _LOCK:
        listening = _LISTENER is not None
        port = _LISTENER_PORT
        bind_host = _LISTENER_HOST
        connected = _CLIENT_SOCK is not None
        addr = _CLIENT_ADDR
    connect_back = None
    if listening and port is not None:
        ips = _get_local_ips() if bind_host == "0.0.0.0" else [bind_host or "127.0.0.1"]
        connect_back = [f"{ip}:{port}" for ip in ips]
    return {
        "listening": listening,
        "port": port,
        "bind_host": bind_host,
        "connect_back": connect_back,
        "connected": connected,
        "client_address": f"{addr[0]}:{addr[1]}" if addr else None,
    }


def _send_command_blocking(command: str, timeout: float = _RECV_TIMEOUT) -> str:
    'Send command and read output to connected client in sync context (Bring End Marks) .'
    global _CLIENT_SOCK, _CLIENT_ADDR
    with _LOCK:
        client = _CLIENT_SOCK
    if client is None:
        return 'Error: no client connected. Start the listener and wait for an authorized target connection before sending commands.'
    # 使用结束标记以便可靠地截断输出
    wrapped = f"{command.strip()}\necho {_END_MARKER}\n"
    try:
        client.settimeout(timeout)
        client.sendall(wrapped.encode("utf-8", errors="replace"))
        data = b""
        while True:
            try:
                chunk = client.recv(_RECV_CHUNK)
                if not chunk:
                    break
                data += chunk
                if _END_MARKER.encode() in data:
                    break
            except socket.timeout:
                break
        text = data.decode("utf-8", errors="replace")
        if _END_MARKER in text:
            text = text.split(_END_MARKER)[0].strip()
        return text or '(No output)'
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        with _LOCK:
            if _CLIENT_SOCK is client:
                _CLIENT_SOCK = None
                _CLIENT_ADDR = None
        return f"Connection disconnected: {e}"
    except Exception as e:
        return f"Execution exception: {e}"


# ---------------------------------------------------------------------------
# MCP 服务与工具
# ---------------------------------------------------------------------------

app = FastMCP(
    name="reverse-shell",
    instructions='Optional privileged reverse-shell MCP: create a local TCP listener, wait for an authorized target connection and exchange commands. The outer tool gate does not sandbox the connected client or child OS authority.',
)


@app.tool(
    description='Start one TCP reverse-shell listener on the specified port. The target callback must be separately authorized. Defaults to loopback (127.0.0.1). Non-loopback binding requires the operator setting REVERSE_SHELL_ALLOW_NON_LOOPBACK=true. After opt-in, bind_host or REVERSE_SHELL_BIND_HOST selects an authorized IPv4 interface; 0.0.0.0 exposes all interfaces. Supports one listener/client; plaintext, no implant authentication.',
)
def reverse_shell_start_listener(port: int, bind_host: str | None = None) -> str:
    """Start reverse shell listener on the given port (e.g. 4444)."""
    if port < 1 or port > 65535:
        return 'Port must be between 1 and 65535.'
    host = bind_host if bind_host is not None else os.environ.get("REVERSE_SHELL_BIND_HOST", "127.0.0.1")
    try:
        host = str(ipaddress.IPv4Address(host))
    except (ipaddress.AddressValueError, TypeError):
        return "bind_host must be an IPv4 interface address (default 127.0.0.1; explicit 0.0.0.0 opts into all interfaces)."
    if not ipaddress.IPv4Address(host).is_loopback and os.environ.get("REVERSE_SHELL_ALLOW_NON_LOOPBACK") != "true":
        return "Non-loopback binding requires operator opt-in: REVERSE_SHELL_ALLOW_NON_LOOPBACK=true. The bind_host tool argument alone is not authorization."
    return _start_listener(port, host)


@app.tool(
    description='Stop the reverse-shell listener and disconnect the current client.',
)
def reverse_shell_stop_listener() -> str:
    """Stop the listener and disconnect the current client."""
    return _stop_listener()


@app.tool(
    description='Return listener state/port and current client connection/address.',
)
def reverse_shell_status() -> str:
    """Get listener and client connection status."""
    s = _status()
    lines = [
        f"Listening: {s['listening']}",
        f"Port: {s['port']}",
        f"Bind host: {s['bind_host'] or '-'}",
        f"Callback addresses (authorized target): {', '.join(s['connect_back']) if s.get('connect_back') else '-'}",
        f"Connected: {s['connected']}",
        f"Client: {s['client_address'] or '-'}",
    ]
    return "\n".join(lines)


@app.tool(
    description="Send an authorized command to the connected reverse-shell client and return output. Requires an existing client connection.",
)
async def reverse_shell_send_command(command: str) -> str:
    """Send a command to the connected reverse shell client and return output."""
    # 在线程池中执行阻塞的 socket I/O，避免长时间占用 MCP 主线程，使 status/stop_listener 等仍可响应
    return await asyncio.to_thread(_send_command_blocking, command)


@app.tool(
    description="Disconnect the current client while leaving the listener open for another authorized connection.",
)
def reverse_shell_disconnect() -> str:
    """Disconnect the current client without stopping the listener."""
    return _disconnect_client()


if __name__ == "__main__":
    app.run(transport="stdio")
