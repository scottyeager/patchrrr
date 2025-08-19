#!/usr/bin/env python

import ctypes
import ctypes.util
import select
import signal
import sys
from typing import Set, Tuple

# This list is the "source of truth" for your MIDI setup.
# Use the format "Client Name:Port Name" or "Client Number:Port Number".
DESIRED_CONNECTIONS = [
    ("Midi Through:Midi Through Port-0", "Pure Data:Pure Data Midi-In 1"),
    # Example: ("20:0", "128:0"),
]

# --- ctypes ALSA Library Definitions ---

# Find and load the ALSA library
libasound_path = ctypes.util.find_library("asound")
if not libasound_path:
    print("ALSA library (libasound) not found.", file=sys.stderr)
    sys.exit(1)
try:
    alsalib = ctypes.CDLL(libasound_path)
except OSError as e:
    print(f"Error loading ALSA library: {e}", file=sys.stderr)
    sys.exit(1)

# --- Basic ALSA Types and Structures ---
snd_seq_t = ctypes.c_void_p
snd_seq_client_info_t = ctypes.c_void_p
snd_seq_port_info_t = ctypes.c_void_p
snd_seq_port_subscribe_t = ctypes.c_void_p
snd_seq_query_subscribe_t = ctypes.c_void_p


class snd_seq_addr(ctypes.Structure):
    _fields_ = [("client", ctypes.c_ubyte), ("port", ctypes.c_ubyte)]


class snd_seq_event(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("flags", ctypes.c_ubyte),
        ("tag", ctypes.c_char),
        ("queue", ctypes.c_ubyte),
        ("time", ctypes.c_void_p),  # snd_seq_timestamp_t
        ("source", snd_seq_addr),
        ("dest", snd_seq_addr),
        ("data", ctypes.c_void_p),
    ]  # union


# --- ALSA Constants ---
SND_SEQ_OPEN_DUPLEX = 2
SND_SEQ_NONBLOCK = 1
SND_SEQ_PORT_CAP_WRITE = 1 << 1
SND_SEQ_PORT_CAP_READ = 1 << 0
SND_SEQ_QUERY_SUBS_READ = 1

# Port types
SND_SEQ_PORT_TYPE_APPLICATION = 1

# Event types that trigger a reconciliation
RELEVANT_EVENTS = {60, 61, 62, 63, 64, 65, 66, 67}

# --- ALSA Function Prototypes ---
# Suppress the default ALSA error handler
SND_ERROR_HANDLER_T = ctypes.CFUNCTYPE(
    None, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p
)
alsalib.snd_lib_error_set_handler.argtypes = [SND_ERROR_HANDLER_T]

# Sequencer handle
alsalib.snd_seq_open.argtypes = [
    ctypes.POINTER(snd_seq_t),
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_int,
]
alsalib.snd_seq_close.argtypes = [snd_seq_t]
alsalib.snd_seq_set_client_name.argtypes = [snd_seq_t, ctypes.c_char_p]
alsalib.snd_seq_client_id.argtypes = [snd_seq_t]
alsalib.snd_seq_client_id.restype = ctypes.c_int

# Port creation
alsalib.snd_seq_create_simple_port.argtypes = [
    snd_seq_t,
    ctypes.c_char_p,
    ctypes.c_uint,
    ctypes.c_uint,
]
alsalib.snd_seq_create_simple_port.restype = ctypes.c_int

# Polling for events
alsalib.snd_seq_poll_descriptors_count.argtypes = [snd_seq_t, ctypes.c_short]
alsalib.snd_seq_poll_descriptors.argtypes = [
    snd_seq_t,
    ctypes.c_void_p,
    ctypes.c_uint,
    ctypes.c_short,
]  # pollfd*
alsalib.snd_seq_event_input.argtypes = [
    snd_seq_t,
    ctypes.POINTER(ctypes.POINTER(snd_seq_event)),
]
alsalib.snd_seq_event_input.restype = ctypes.c_int

# Creating subscriptions (making connections)
alsalib.snd_seq_port_subscribe_malloc.argtypes = [
    ctypes.POINTER(snd_seq_port_subscribe_t)
]
alsalib.snd_seq_port_subscribe_set_sender.argtypes = [
    snd_seq_port_subscribe_t,
    ctypes.POINTER(snd_seq_addr),
]
alsalib.snd_seq_port_subscribe_set_dest.argtypes = [
    snd_seq_port_subscribe_t,
    ctypes.POINTER(snd_seq_addr),
]
alsalib.snd_seq_subscribe_port.argtypes = [snd_seq_t, snd_seq_port_subscribe_t]
alsalib.snd_seq_port_subscribe_free.argtypes = [snd_seq_port_subscribe_t]
alsalib.snd_seq_parse_address.argtypes = [
    snd_seq_t,
    ctypes.POINTER(snd_seq_addr),
    ctypes.c_char_p,
]

# Querying clients and ports
alsalib.snd_seq_client_info_malloc.argtypes = [ctypes.POINTER(snd_seq_client_info_t)]
alsalib.snd_seq_client_info_set_client.argtypes = [snd_seq_client_info_t, ctypes.c_int]
alsalib.snd_seq_query_next_client.argtypes = [snd_seq_t, snd_seq_client_info_t]
alsalib.snd_seq_client_info_get_client.argtypes = [snd_seq_client_info_t]
alsalib.snd_seq_client_info_get_name.argtypes = [snd_seq_client_info_t]
alsalib.snd_seq_client_info_get_name.restype = ctypes.c_char_p
alsalib.snd_seq_client_info_free.argtypes = [snd_seq_client_info_t]
alsalib.snd_seq_port_info_malloc.argtypes = [ctypes.POINTER(snd_seq_port_info_t)]
alsalib.snd_seq_port_info_set_client.argtypes = [snd_seq_port_info_t, ctypes.c_int]
alsalib.snd_seq_port_info_set_port.argtypes = [snd_seq_port_info_t, ctypes.c_int]
alsalib.snd_seq_query_next_port.argtypes = [snd_seq_t, snd_seq_port_info_t]
alsalib.snd_seq_port_info_get_name.argtypes = [snd_seq_port_info_t]
alsalib.snd_seq_port_info_get_name.restype = ctypes.c_char_p
alsalib.snd_seq_port_info_get_addr.argtypes = [snd_seq_port_info_t]
alsalib.snd_seq_port_info_get_addr.restype = ctypes.POINTER(snd_seq_addr)
alsalib.snd_seq_port_info_get_capability.argtypes = [snd_seq_port_info_t]
alsalib.snd_seq_port_info_get_capability.restype = ctypes.c_uint
alsalib.snd_seq_port_info_free.argtypes = [snd_seq_port_info_t]
alsalib.snd_seq_get_any_port_info.argtypes = [
    snd_seq_t,
    ctypes.c_int,
    ctypes.c_int,
    snd_seq_port_info_t,
]

# Querying subscriptions (reading connections)
alsalib.snd_seq_query_subscribe_malloc.argtypes = [
    ctypes.POINTER(snd_seq_query_subscribe_t)
]
alsalib.snd_seq_query_subscribe_set_root.argtypes = [
    snd_seq_query_subscribe_t,
    ctypes.POINTER(snd_seq_addr),
]
alsalib.snd_seq_query_subscribe_set_type.argtypes = [
    snd_seq_query_subscribe_t,
    ctypes.c_int,
]
alsalib.snd_seq_query_subscribe_set_index.argtypes = [
    snd_seq_query_subscribe_t,
    ctypes.c_int,
]
alsalib.snd_seq_query_port_subscribers.argtypes = [snd_seq_t, snd_seq_query_subscribe_t]
alsalib.snd_seq_query_subscribe_get_addr.argtypes = [snd_seq_query_subscribe_t]
alsalib.snd_seq_query_subscribe_get_addr.restype = ctypes.POINTER(snd_seq_addr)
alsalib.snd_seq_query_subscribe_get_index.argtypes = [snd_seq_query_subscribe_t]
alsalib.snd_seq_query_subscribe_get_index.restype = ctypes.c_int
alsalib.snd_seq_query_subscribe_free.argtypes = [snd_seq_query_subscribe_t]


# --- Global State ---
seq = None
running = True


# --- Helper Functions ---
def get_current_state() -> Tuple[Set[str], Set[Tuple[str, str]]]:
    """
    Gets the current state of the ALSA sequencer.
    Returns (all_ports, all_connections)
    """
    if not seq:
        return set(), set()

    available_ports, connections = set(), set()
    client_ports = {}  # { client_id: { port_id: "Full Port String" } }

    cinfo_ptr = snd_seq_client_info_t()
    pinfo_ptr = snd_seq_port_info_t()
    alsalib.snd_seq_client_info_malloc(ctypes.byref(cinfo_ptr))
    alsalib.snd_seq_port_info_malloc(ctypes.byref(pinfo_ptr))

    # First pass: Get all clients and ports, build a map for easy lookup
    alsalib.snd_seq_client_info_set_client(cinfo_ptr, -1)
    while alsalib.snd_seq_query_next_client(seq, cinfo_ptr) >= 0:
        client_id = alsalib.snd_seq_client_info_get_client(cinfo_ptr)
        client_name = alsalib.snd_seq_client_info_get_name(cinfo_ptr).decode("utf-8")
        client_ports[client_id] = {}

        alsalib.snd_seq_port_info_set_client(pinfo_ptr, client_id)
        alsalib.snd_seq_port_info_set_port(pinfo_ptr, -1)
        while alsalib.snd_seq_query_next_port(seq, pinfo_ptr) >= 0:
            addr = alsalib.snd_seq_port_info_get_addr(pinfo_ptr).contents
            port_name = alsalib.snd_seq_port_info_get_name(pinfo_ptr).decode("utf-8")
            full_port_str = f"{client_name}:{port_name}"
            available_ports.add(full_port_str)
            client_ports[addr.client][addr.port] = full_port_str

    # Second pass: Iterate through writable ports and query their subscribers
    for client_id, ports in client_ports.items():
        for port_id, source_full_str in ports.items():
            alsalib.snd_seq_get_any_port_info(seq, client_id, port_id, pinfo_ptr)
            caps = alsalib.snd_seq_port_info_get_capability(pinfo_ptr)

            if caps & SND_SEQ_PORT_CAP_WRITE:  # This is a source port
                query_ptr = snd_seq_query_subscribe_t()
                alsalib.snd_seq_query_subscribe_malloc(ctypes.byref(query_ptr))
                sender_addr = snd_seq_addr(client=client_id, port=port_id)
                alsalib.snd_seq_query_subscribe_set_root(
                    query_ptr, ctypes.byref(sender_addr)
                )
                alsalib.snd_seq_query_subscribe_set_type(
                    query_ptr, SND_SEQ_QUERY_SUBS_READ
                )
                alsalib.snd_seq_query_subscribe_set_index(query_ptr, 0)

                while alsalib.snd_seq_query_port_subscribers(seq, query_ptr) >= 0:
                    sub_addr = alsalib.snd_seq_query_subscribe_get_addr(
                        query_ptr
                    ).contents
                    try:
                        dest_full_str = client_ports[sub_addr.client][sub_addr.port]
                        connections.add((source_full_str, dest_full_str))
                    except KeyError:
                        # Connection to a non-existent port, can be ignored
                        pass
                    index = alsalib.snd_seq_query_subscribe_get_index(query_ptr)
                    alsalib.snd_seq_query_subscribe_set_index(query_ptr, index + 1)

                alsalib.snd_seq_query_subscribe_free(query_ptr)

    alsalib.snd_seq_client_info_free(cinfo_ptr)
    alsalib.snd_seq_port_info_free(pinfo_ptr)
    return available_ports, connections


def connect_alsa_ports(source_str: str, dest_str: str) -> bool:
    """Connects two ALSA ports using the subscription mechanism."""
    if not seq:
        return False

    sender = snd_seq_addr()
    dest = snd_seq_addr()

    if (
        alsalib.snd_seq_parse_address(
            seq, ctypes.byref(sender), source_str.encode("utf-8")
        )
        < 0
    ):
        print(f"  [ERROR] Cannot parse source address: {source_str}", file=sys.stderr)
        return False
    if (
        alsalib.snd_seq_parse_address(seq, ctypes.byref(dest), dest_str.encode("utf-8"))
        < 0
    ):
        print(
            f"  [ERROR] Cannot parse destination address: {dest_str}", file=sys.stderr
        )
        return False

    sub_ptr = snd_seq_port_subscribe_t()
    alsalib.snd_seq_port_subscribe_malloc(ctypes.byref(sub_ptr))
    alsalib.snd_seq_port_subscribe_set_sender(sub_ptr, ctypes.byref(sender))
    alsalib.snd_seq_port_subscribe_set_dest(sub_ptr, ctypes.byref(dest))

    success = False
    if alsalib.snd_seq_subscribe_port(seq, sub_ptr) == 0:
        print(f"  [OK] Ensuring connection: {source_str} -> {dest_str}")
        success = True

    alsalib.snd_seq_port_subscribe_free(sub_ptr)
    return success


def reconcile_connections():
    """Compares the desired state with the current state and makes connections."""
    print("\n--- Reconciling ALSA MIDI Connections ---")
    available_ports, current_connections = get_current_state()

    if not available_ports:
        print("  [WARN] No ALSA MIDI ports available.")
        return

    for source, dest in DESIRED_CONNECTIONS:
        if (source, dest) in current_connections:
            continue
        if source in available_ports and dest in available_ports:
            print("  [!] Missing connection detected. Restoring...")
            connect_alsa_ports(source, dest)


def signal_handler(sig, frame):
    """Handles signals and sets the running flag to false."""
    global running
    print("\nSignal received, shutting down...")
    running = False


# --- Main Application ---
def main():
    global seq

    seq_ptr = snd_seq_t()
    if (
        alsalib.snd_seq_open(
            ctypes.byref(seq_ptr), b"default", SND_SEQ_OPEN_DUPLEX, SND_SEQ_NONBLOCK
        )
        < 0
    ):
        print("Error opening ALSA sequencer.", file=sys.stderr)
        sys.exit(1)
    seq = seq_ptr

    alsalib.snd_seq_set_client_name(seq, b"py-alsa-ctypes-manager")

    # Create a simple port for receiving events
    input_port = alsalib.snd_seq_create_simple_port(
        seq,
        b"input",
        SND_SEQ_PORT_CAP_READ,  # This port can receive events
        SND_SEQ_PORT_TYPE_APPLICATION,
    )

    if input_port < 0:
        print("Error creating input port.", file=sys.stderr)
        alsalib.snd_seq_close(seq)
        sys.exit(1)

    print(f"Created input port: {input_port}")

    # Subscribe to the announce port to receive system-wide events
    sub_ptr = snd_seq_port_subscribe_t()
    alsalib.snd_seq_port_subscribe_malloc(ctypes.byref(sub_ptr))

    sender = snd_seq_addr(client=0, port=1)  # System Announce port is 0:1
    dest_client_id = alsalib.snd_seq_client_id(seq)
    dest = snd_seq_addr(client=dest_client_id, port=input_port)  # Use the created port
    alsalib.snd_seq_port_subscribe_set_sender(sub_ptr, ctypes.byref(sender))
    alsalib.snd_seq_port_subscribe_set_dest(sub_ptr, ctypes.byref(dest))

    if alsalib.snd_seq_subscribe_port(seq, sub_ptr) < 0:
        print("Could not subscribe to announce port.", file=sys.stderr)
        alsalib.snd_seq_close(seq)
        sys.exit(1)

    print("Successfully subscribed to announce port.")
    alsalib.snd_seq_port_subscribe_free(sub_ptr)

    # Set up polling
    poll_count = alsalib.snd_seq_poll_descriptors_count(seq, select.POLLIN)

    # The C struct pollfd has {int fd; short events; short revents;}
    class pollfd(ctypes.Structure):
        _fields_ = [
            ("fd", ctypes.c_int),
            ("events", ctypes.c_short),
            ("revents", ctypes.c_short),
        ]

    poll_fds = (pollfd * poll_count)()
    alsalib.snd_seq_poll_descriptors(
        seq, ctypes.byref(poll_fds), poll_count, select.POLLIN
    )

    poller = select.poll()
    for pfd in poll_fds:
        poller.register(pfd.fd, select.POLLIN)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        reconcile_connections()
        print(
            "\n--- Initial setup complete. Waiting for ALSA events... (Press Ctrl+C to exit) ---"
        )

        while running:
            if poller.poll(1000):  # 1 second timeout
                event_ptr = ctypes.POINTER(snd_seq_event)()
                reconciliation_needed = False
                while alsalib.snd_seq_event_input(seq, ctypes.byref(event_ptr)) >= 0:
                    event = event_ptr.contents
                    if event and event.type in RELEVANT_EVENTS:
                        reconciliation_needed = True

                if reconciliation_needed:
                    print("ALSA Event detected, triggering reconciliation.")
                    reconcile_connections()

    finally:
        print("Exiting ALSA connection manager.")
        if seq:
            alsalib.snd_seq_close(seq)


if __name__ == "__main__":
    # Define a no-op handler to suppress ALSA's default error messages
    @SND_ERROR_HANDLER_T
    def py_error_handler(filename, line, function, err, fmt):
        pass

    alsalib.snd_lib_error_set_handler(py_error_handler)

    main()
