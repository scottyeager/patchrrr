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
    ("Pure Data:Pure Data Midi-Out 1", "Pure Data:Pure Data Midi-In 1"),
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
SND_SEQ_PORT_CAP_WRITE = 1 << 1  # Port can receive data (input port)
SND_SEQ_PORT_CAP_SUBS_WRITE = 1 << 5
SND_SEQ_PORT_CAP_READ = 1 << 0  # Port can send data (output port)
SND_SEQ_QUERY_SUBS_READ = 1

# Port types
SND_SEQ_PORT_TYPE_APPLICATION = 1

# Event types that trigger a reconciliation
# Include client/port creation, deletion, and change events
RELEVANT_EVENTS = {
    60,  # SND_SEQ_EVENT_CLIENT_START
    61,  # SND_SEQ_EVENT_CLIENT_EXIT
    62,  # SND_SEQ_EVENT_CLIENT_CHANGE
    63,  # SND_SEQ_EVENT_PORT_START
    64,  # SND_SEQ_EVENT_PORT_EXIT
    65,  # SND_SEQ_EVENT_PORT_CHANGE
    66,  # SND_SEQ_EVENT_PORT_SUBSCRIBED
    67,  # SND_SEQ_EVENT_PORT_UNSUBSCRIBED
}

# --- ALSA Function Prototypes ---
# Error handler to suppress ALSA messages
SND_ERROR_HANDLER_T = ctypes.CFUNCTYPE(
    None, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p
)


def null_error_handler(file, line, function, err, fmt):
    """Null error handler to suppress ALSA error messages"""
    pass


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

# Connection functions
alsalib.snd_seq_connect_from.argtypes = [
    snd_seq_t,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
]
alsalib.snd_seq_connect_from.restype = ctypes.c_int

# Query subscription (check existing connections)
alsalib.snd_seq_get_port_subscription.argtypes = [
    snd_seq_t,
    snd_seq_port_subscribe_t,
]
alsalib.snd_seq_get_port_subscription.restype = ctypes.c_int

# Error string function
alsalib.snd_strerror.argtypes = [ctypes.c_int]
alsalib.snd_strerror.restype = ctypes.c_char_p

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

    # Second pass: Iterate through readable (output) ports and query their subscribers
    for client_id, ports in client_ports.items():
        for port_id, source_full_str in ports.items():
            alsalib.snd_seq_get_any_port_info(seq, client_id, port_id, pinfo_ptr)
            caps = alsalib.snd_seq_port_info_get_capability(pinfo_ptr)

            # Check for both READ and WRITE capabilities to find all ports
            if caps & (SND_SEQ_PORT_CAP_READ | SND_SEQ_PORT_CAP_WRITE):
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


def debug_port_capabilities(port_str: str) -> str:
    """Returns a string describing the capabilities of a port for debugging."""
    if not seq:
        return "sequencer not available"

    addr = snd_seq_addr()
    if (
        alsalib.snd_seq_parse_address(seq, ctypes.byref(addr), port_str.encode("utf-8"))
        < 0
    ):
        return "cannot parse address"

    pinfo_ptr = snd_seq_port_info_t()
    alsalib.snd_seq_port_info_malloc(ctypes.byref(pinfo_ptr))

    if alsalib.snd_seq_get_any_port_info(seq, addr.client, addr.port, pinfo_ptr) < 0:
        alsalib.snd_seq_port_info_free(pinfo_ptr)
        return "cannot get port info"

    caps = alsalib.snd_seq_port_info_get_capability(pinfo_ptr)
    
    # Get port direction - need to define the constants
    SND_SEQ_PORT_DIR_INPUT = 1
    SND_SEQ_PORT_DIR_OUTPUT = 2
    
    # Check if we can get direction from the port info structure
    # Note: This is a simplified approach since we don't have direct access to direction
    
    cap_strings = []
    if caps & SND_SEQ_PORT_CAP_READ:
        cap_strings.append("READ")
    if caps & SND_SEQ_PORT_CAP_WRITE:
        cap_strings.append("WRITE")
    if caps & SND_SEQ_PORT_CAP_SUBS_WRITE:
        cap_strings.append("SUBS_WRITE")
    if caps & (1 << 4):  # SND_SEQ_PORT_CAP_SUBS_READ
        cap_strings.append("SUBS_READ")
    
    # Determine port type based on capabilities
    if caps & SND_SEQ_PORT_CAP_READ and caps & SND_SEQ_PORT_CAP_SUBS_READ:
        cap_strings.append("OUTPUT")
    if caps & SND_SEQ_PORT_CAP_WRITE and caps & SND_SEQ_PORT_CAP_SUBS_WRITE:
        cap_strings.append("INPUT")

    alsalib.snd_seq_port_info_free(pinfo_ptr)
    return f"caps=0x{caps:x} [{', '.join(cap_strings)}]"


def connect_alsa_ports(source_str: str, dest_str: str) -> bool:
    """Connects two ALSA ports using subscription mechanism, similar to aconnect."""
    if not seq:
        return False

    # Debug port capabilities
    print(f"  [DEBUG] Source '{source_str}': {debug_port_capabilities(source_str)}")
    print(f"  [DEBUG] Dest '{dest_str}': {debug_port_capabilities(dest_str)}")

    sender = snd_seq_addr()
    dest = snd_seq_addr()

    result = alsalib.snd_seq_parse_address(
        seq, ctypes.byref(sender), source_str.encode("utf-8")
    )
    if result < 0:
        print(
            f"  [ERROR] Cannot parse source address '{source_str}': {alsa_strerror(result)}",
            file=sys.stderr,
        )
        return False

    result = alsalib.snd_seq_parse_address(
        seq, ctypes.byref(dest), dest_str.encode("utf-8")
    )
    if result < 0:
        print(
            f"  [ERROR] Cannot parse destination address '{dest_str}': {alsa_strerror(result)}",
            file=sys.stderr,
        )
        return False

    # Check port capabilities - source must be readable, dest must be writable
    pinfo_ptr = snd_seq_port_info_t()
    alsalib.snd_seq_port_info_malloc(ctypes.byref(pinfo_ptr))

    # Check source capabilities
    if alsalib.snd_seq_get_any_port_info(seq, sender.client, sender.port, pinfo_ptr) < 0:
        alsalib.snd_seq_port_info_free(pinfo_ptr)
        print(f"  [ERROR] Cannot get source port info")
        return False
    
    source_caps = alsalib.snd_seq_port_info_get_capability(pinfo_ptr)
    if not (source_caps & SND_SEQ_PORT_CAP_READ):
        alsalib.snd_seq_port_info_free(pinfo_ptr)
        print(f"  [ERROR] Source port is not readable (cannot send data)")
        return False

    # Check destination capabilities
    if alsalib.snd_seq_get_any_port_info(seq, dest.client, dest.port, pinfo_ptr) < 0:
        alsalib.snd_seq_port_info_free(pinfo_ptr)
        print(f"  [ERROR] Cannot get destination port info")
        return False
    
    dest_caps = alsalib.snd_seq_port_info_get_capability(pinfo_ptr)
    if not (dest_caps & SND_SEQ_PORT_CAP_WRITE):
        alsalib.snd_seq_port_info_free(pinfo_ptr)
        print(f"  [ERROR] Destination port is not writable (cannot receive data)")
        return False

    alsalib.snd_seq_port_info_free(pinfo_ptr)

    # Check if connection already exists
    query_ptr = snd_seq_query_subscribe_t()
    alsalib.snd_seq_query_subscribe_malloc(ctypes.byref(query_ptr))
    alsalib.snd_seq_query_subscribe_set_root(query_ptr, ctypes.byref(sender))
    alsalib.snd_seq_query_subscribe_set_type(query_ptr, SND_SEQ_QUERY_SUBS_READ)
    alsalib.snd_seq_query_subscribe_set_index(query_ptr, 0)
    
    connection_exists = False
    while alsalib.snd_seq_query_port_subscribers(seq, query_ptr) >= 0:
        sub_addr = alsalib.snd_seq_query_subscribe_get_addr(query_ptr).contents
        if sub_addr.client == dest.client and sub_addr.port == dest.port:
            connection_exists = True
            break
        index = alsalib.snd_seq_query_subscribe_get_index(query_ptr)
        alsalib.snd_seq_query_subscribe_set_index(query_ptr, index + 1)
    
    alsalib.snd_seq_query_subscribe_free(query_ptr)
    
    if connection_exists:
        print(f"  [OK] Connection already exists: {source_str} -> {dest_str}")
        return True

    # Create subscription (connection)
    sub_ptr = snd_seq_port_subscribe_t()
    alsalib.snd_seq_port_subscribe_malloc(ctypes.byref(sub_ptr))
    alsalib.snd_seq_port_subscribe_set_sender(sub_ptr, ctypes.byref(sender))
    alsalib.snd_seq_port_subscribe_set_dest(sub_ptr, ctypes.byref(dest))
    alsalib.snd_seq_port_subscribe_set_queue(sub_ptr, 0)
    alsalib.snd_seq_port_subscribe_set_exclusive(sub_ptr, 0)
    alsalib.snd_seq_port_subscribe_set_time_update(sub_ptr, 0)
    alsalib.snd_seq_port_subscribe_set_time_real(sub_ptr, 0)

    # Check if already subscribed
    if alsalib.snd_seq_get_port_subscription(seq, sub_ptr) == 0:
        print(f"  [OK] Connection already exists: {source_str} -> {dest_str}")
        alsalib.snd_seq_port_subscribe_free(sub_ptr)
        return True

    result = alsalib.snd_seq_subscribe_port(seq, sub_ptr)
    if result == 0:
        print(f"  [OK] Connected: {source_str} -> {dest_str}")
        success = True
    else:
        print(
            f"  [ERROR] Failed to connect {source_str} -> {dest_str}: {alsa_strerror(result)}",
            file=sys.stderr,
        )
        success = False

    alsalib.snd_seq_port_subscribe_free(sub_ptr)
    return success


def list_available_ports():
    """Lists all available MIDI ports for debugging."""
    print("\n--- Available MIDI Ports ---")
    available_ports, _ = get_current_state()

    if not available_ports:
        print("  No ports available")
        return

    # Get detailed port info
    cinfo_ptr = snd_seq_client_info_t()
    pinfo_ptr = snd_seq_port_info_t()
    alsalib.snd_seq_client_info_malloc(ctypes.byref(cinfo_ptr))
    alsalib.snd_seq_port_info_malloc(ctypes.byref(pinfo_ptr))

    alsalib.snd_seq_client_info_set_client(cinfo_ptr, -1)
    while alsalib.snd_seq_query_next_client(seq, cinfo_ptr) >= 0:
        client_id = alsalib.snd_seq_client_info_get_client(cinfo_ptr)
        client_name = alsalib.snd_seq_client_info_get_name(cinfo_ptr).decode("utf-8")

        alsalib.snd_seq_port_info_set_client(pinfo_ptr, client_id)
        alsalib.snd_seq_port_info_set_port(pinfo_ptr, -1)
        while alsalib.snd_seq_query_next_port(seq, pinfo_ptr) >= 0:
            addr = alsalib.snd_seq_port_info_get_addr(pinfo_ptr).contents
            port_name = alsalib.snd_seq_port_info_get_name(pinfo_ptr).decode("utf-8")
            caps = alsalib.snd_seq_port_info_get_capability(pinfo_ptr)

            cap_str = []
            if caps & SND_SEQ_PORT_CAP_READ:
                cap_str.append("READ")
            if caps & SND_SEQ_PORT_CAP_WRITE:
                cap_str.append("WRITE")
            if caps & SND_SEQ_PORT_CAP_SUBS_WRITE:
                cap_str.append("SUBS_WRITE")
            if caps & (1 << 4):  # SND_SEQ_PORT_CAP_SUBS_READ
                cap_str.append("SUBS_READ")

            full_port_str = f"{client_name}:{port_name}"
            print(
                f"  {addr.client:3d}:{addr.port:<2d} {full_port_str:<40} [{', '.join(cap_str)}]"
            )

    alsalib.snd_seq_client_info_free(cinfo_ptr)
    alsalib.snd_seq_port_info_free(pinfo_ptr)


def reconcile_connections():
    """Compares the desired state with the current state and makes connections."""
    print("\n--- Reconciling ALSA MIDI Connections ---")
    available_ports, current_connections = get_current_state()

    if not available_ports:
        print("  [WARN] No ALSA MIDI ports available.")
        list_available_ports()
        return

    print(f"Found {len(available_ports)} available ports")
    print(f"Found {len(current_connections)} existing connections")

    for source, dest in DESIRED_CONNECTIONS:
        if (source, dest) in current_connections:
            print(f"  [OK] Connection already exists: {source} -> {dest}")
            continue

        if source not in available_ports:
            print(f"  [WARN] Source port not available: {source}")
            continue

        if dest not in available_ports:
            print(f"  [WARN] Destination port not available: {dest}")
            continue

        print("  [!] Missing connection detected. Attempting to connect...")
        connect_alsa_ports(source, dest)

    # Show available ports for debugging
    if len(DESIRED_CONNECTIONS) > 0 and not any(
        source in available_ports and dest in available_ports
        for source, dest in DESIRED_CONNECTIONS
    ):
        list_available_ports()


def alsa_strerror(error_code: int) -> str:
    """Converts ALSA error code to human-readable string."""
    error_str = alsalib.snd_strerror(error_code)
    return (
        error_str.decode("utf-8") if error_str else f"Unknown error code {error_code}"
    )


def signal_handler(sig, frame):
    """Handles signals and sets the running flag to false."""
    global running
    print("\nSignal received, shutting down...")
    running = False


# --- Main Application ---
def main():
    global seq

    # Install null error handler to suppress ALSA error messages
    null_handler = SND_ERROR_HANDLER_T(null_error_handler)
    alsalib.snd_lib_error_set_handler(null_handler)

    seq_ptr = snd_seq_t()
    result = alsalib.snd_seq_open(
        ctypes.byref(seq_ptr), b"default", SND_SEQ_OPEN_DUPLEX, SND_SEQ_NONBLOCK
    )
    if result < 0:
        print(f"Error opening ALSA sequencer: {alsa_strerror(result)}", file=sys.stderr)
        sys.exit(1)
    seq = seq_ptr

    alsalib.snd_seq_set_client_name(seq, b"py-alsa-ctypes-manager")

    # Create a simple port for receiving events
    input_port = alsalib.snd_seq_create_simple_port(
        seq,
        b"input",
        SND_SEQ_PORT_CAP_WRITE | SND_SEQ_PORT_CAP_SUBS_WRITE,
        SND_SEQ_PORT_TYPE_APPLICATION,
    )

    if input_port < 0:
        print(
            f"Error creating input port: {alsa_strerror(input_port)}", file=sys.stderr
        )
        alsalib.snd_seq_close(seq)
        sys.exit(1)

    # Connect from system announce port (0:1) to our port
    connect_result = alsalib.snd_seq_connect_from(seq, input_port, 0, 1)
    if connect_result < 0:
        print(
            f"Could not connect from announce port: {alsa_strerror(connect_result)}",
            file=sys.stderr,
        )
        alsalib.snd_seq_close(seq)
        sys.exit(1)

    print("Successfully connected to announce port for events.")

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
    main()
