#!/usr/bin/env python

import ctypes
import ctypes.util
import queue
import signal
import sys
from typing import Set, Tuple

# This list remains the same. It is the "source of truth" for your setup.
DESIRED_CONNECTIONS = [
    ("pure_data:output_1", "system:playback_9"),
    ("pure_data:output_2", "system:playback_10"),
]

# --- ctypes JACK Library Definitions ---

# Find and load the JACK library
libjack_path = ctypes.util.find_library("jack")
if not libjack_path:
    print("JACK library not found. Please install it.", file=sys.stderr)
    sys.exit(1)
try:
    jacklib = ctypes.CDLL(libjack_path)
except OSError as e:
    print(f"Error loading JACK library: {e}", file=sys.stderr)
    sys.exit(1)

# Define JACK data types
jack_port_id_t = ctypes.c_uint32
jack_uuid_t = ctypes.c_uint64
jack_client_t = ctypes.c_void_p
jack_port_t = ctypes.c_void_p


# From jack/jack.h (abbreviated)
class JackOptions:
    JackNullOption = 0x00
    JackNoStartServer = 0x01


class JackStatus:
    JackServerFailed = 0x10


# Define C function prototypes for callbacks
ClientCallback = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p)
PortCallback = ctypes.CFUNCTYPE(None, jack_port_id_t, ctypes.c_int, ctypes.c_void_p)
GraphCallback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)

# Define C function prototypes for JACK functions
# Basic client management
jacklib.jack_client_open.argtypes = [
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int),
]
jacklib.jack_client_open.restype = jack_client_t
jacklib.jack_client_close.argtypes = [jack_client_t]
jacklib.jack_activate.argtypes = [jack_client_t]

# Callback setters
jacklib.jack_set_client_registration_callback.argtypes = [
    jack_client_t,
    ClientCallback,
    ctypes.c_void_p,
]
jacklib.jack_set_port_registration_callback.argtypes = [
    jack_client_t,
    PortCallback,
    ctypes.c_void_p,
]
jacklib.jack_set_graph_order_callback.argtypes = [
    jack_client_t,
    GraphCallback,
    ctypes.c_void_p,
]

# Port and connection management
jacklib.jack_get_ports.argtypes = [
    jack_client_t,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
]
jacklib.jack_get_ports.restype = ctypes.POINTER(ctypes.c_char_p)
jacklib.jack_port_by_name.argtypes = [jack_client_t, ctypes.c_char_p]
jacklib.jack_port_by_name.restype = jack_port_t
jacklib.jack_port_get_all_connections.argtypes = [jack_client_t, jack_port_t]
jacklib.jack_port_get_all_connections.restype = ctypes.POINTER(ctypes.c_char_p)
jacklib.jack_connect.argtypes = [jack_client_t, ctypes.c_char_p, ctypes.c_char_p]
jacklib.jack_connect.restype = ctypes.c_int
jacklib.jack_free.argtypes = [ctypes.c_void_p]

# --- Globals for Cross-Thread Communication ---

# The client handle, accessible from the main thread and signal handler
client = None
# A thread-safe queue to send events from JACK callbacks to the main thread
event_queue = queue.Queue()

# --- ctypes-based Replacement Functions (Main Thread Safe) ---


def get_jack_ports() -> Set[str]:
    """Gets a set of all currently available JACK audio ports using ctypes."""
    if not client:
        return set()
    ports_ptr = jacklib.jack_get_ports(client, None, None, 0)
    if not ports_ptr:
        return set()
    ports = set()
    i = 0
    while ports_ptr[i]:
        ports.add(ports_ptr[i].decode("utf-8"))
        i += 1
    jacklib.jack_free(ports_ptr)
    return ports


def get_current_connections() -> Set[Tuple[str, str]]:
    """
    Gets a set of all current connections using ctypes.
    Returns a set of (source, destination) tuples.
    """
    if not client:
        return set()
    connections = set()
    all_ports = get_jack_ports()
    for source_port_name in all_ports:
        source_port = jacklib.jack_port_by_name(
            client, source_port_name.encode("utf-8")
        )
        if not source_port:
            continue
        connections_ptr = jacklib.jack_port_get_all_connections(client, source_port)
        if not connections_ptr:
            continue
        i = 0
        while connections_ptr[i]:
            dest_port_name = connections_ptr[i].decode("utf-8")
            connections.add((source_port_name, dest_port_name))
            i += 1
        jacklib.jack_free(connections_ptr)
    return connections


def connect_jack_ports(source_port: str, destination_port: str) -> bool:
    """Creates a connection using the ctypes jack_connect function."""
    if not client:
        return False
    if (
        jacklib.jack_connect(
            client, source_port.encode("utf-8"), destination_port.encode("utf-8")
        )
        == 0
    ):
        print(f"  [OK] Ensuring connection: {source_port} -> {destination_port}")
        return True
    return False


# --- Core Logic and Callbacks ---


def reconcile_connections():
    """
    Compares the desired state with the current state and makes necessary connections.
    This function is now ONLY called from the main thread.
    """
    print("\n--- Reconciling Connections ---")
    available_ports = get_jack_ports()
    current_connections = get_current_connections()

    if not available_ports:
        print("  [WARN] JACK server not running or no ports available.")
        return

    for source, dest in DESIRED_CONNECTIONS:
        if (source, dest) in current_connections:
            continue
        if source in available_ports and dest in available_ports:
            print("  [!] Missing connection detected. Restoring...")
            connect_jack_ports(source, dest)


# --- Callbacks (Executed in JACK's Notification Thread) ---
# These functions MUST be minimal and non-blocking. Their only job is
# to put an event on the queue for the main thread to process.


def client_callback(
    client_name_ptr: ctypes.c_char_p, registered: int, arg: ctypes.c_void_p
):
    """Callback for client registration events."""
    client_name = client_name_ptr.decode()
    status = "registered" if registered else "unregistered"
    print(f"\nJACK Event: Client '{client_name}' {status}")
    if client_name != "py-jack-ctypes-manager":
        event_queue.put("reconcile")


def port_callback(port_id: jack_port_id_t, registered: int, arg: ctypes.c_void_p):
    """Callback for port registration events."""
    status = "registered" if registered else "unregistered"
    print(f"\nJACK Event: A port was {status}")
    event_queue.put("reconcile")


def graph_callback(arg: ctypes.c_void_p) -> int:
    """Callback for graph reorder events (connections changed)."""
    print("\nJACK Event: Graph order changed")
    event_queue.put("reconcile")
    return 0


def signal_handler(sig, frame):
    """Handles signals and closes the JACK client."""
    print("\nShutting down JACK client...")
    if client:
        jacklib.jack_client_close(client)
    sys.exit(0)


# --- Main Application ---


def main():
    """
    Starts the JACK client, sets callbacks, and enters the main event loop.
    """
    global client

    status = ctypes.c_int()
    client_name = "py-jack-ctypes-manager"
    client = jacklib.jack_client_open(
        client_name.encode(), JackOptions.JackNoStartServer, ctypes.byref(status)
    )

    if not client:
        print("Could not connect to JACK server. Is it running?", file=sys.stderr)
        if status.value & JackStatus.JackServerFailed:
            print("Unable to connect to JACK server", file=sys.stderr)
        sys.exit(1)

    # Keep references to callbacks so they are not garbage-collected
    c_client_callback = ClientCallback(client_callback)
    c_port_callback = PortCallback(port_callback)
    c_graph_callback = GraphCallback(graph_callback)

    jacklib.jack_set_client_registration_callback(client, c_client_callback, None)
    jacklib.jack_set_port_registration_callback(client, c_port_callback, None)
    jacklib.jack_set_graph_order_callback(client, c_graph_callback, None)

    if jacklib.jack_activate(client) != 0:
        print("Cannot activate JACK client.", file=sys.stderr)
        jacklib.jack_client_close(client)
        sys.exit(1)

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        reconcile_connections()
        print(
            "\n--- Initial setup complete. Waiting for JACK events... (Press Ctrl+C to exit) ---"
        )

        while True:
            # This will block efficiently until a callback puts something in the queue
            event = event_queue.get()
            if event == "reconcile":
                reconcile_connections()

    except KeyboardInterrupt:
        pass
    finally:
        print("\nExiting JACK connection manager.")
        if client:
            jacklib.jack_client_close(client)


if __name__ == "__main__":
    main()
