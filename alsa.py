#!/usr/bin/env python

import ctypes
import ctypes.util
import select
import signal
import sys
from typing import Set, Tuple

# This list is the "source of truth" for your MIDI setup.
# Both numbers and names are accepted for clients and ports
DESIRED_CONNECTIONS = [
    # Example: ("Midi Through:Midi Through Port-0", "Pure Data:Pure Data Midi-In 2"),
    # Example: ("Pure Data:2", "14:Midi Through Port-0"),
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
SND_SEQ_PORT_CAP_READ = 1 << 0  # Port can send data (output port)
SND_SEQ_PORT_CAP_WRITE = 1 << 1  # Port can receive data (input port)
SND_SEQ_PORT_CAP_SUBS_READ = 1 << 5
SND_SEQ_PORT_CAP_SUBS_WRITE = 1 << 6
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

# Port direction
SND_SEQ_PORT_DIR_INPUT = 1
SND_SEQ_PORT_DIR_OUTPUT = 2

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
    ctypes.c_short,  # pollfd*
]
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
alsalib.snd_seq_port_info_get_direction.argtypes = [snd_seq_port_info_t]
alsalib.snd_seq_port_info_get_direction.restype = ctypes.c_uint
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


class AlsaManager:
    def __init__(self, desired_connections):
        self.desired_connections = desired_connections
        self.seq = None
        self.running = True
        self.poller = None
        self.poll_fds = None

        # Install null error handler to suppress ALSA error messages
        null_handler = SND_ERROR_HANDLER_T(null_error_handler)
        alsalib.snd_lib_error_set_handler(null_handler)

    def start(self):
        """Opens the ALSA sequencer and sets up for event polling."""
        seq_ptr = snd_seq_t()
        result = alsalib.snd_seq_open(
            ctypes.byref(seq_ptr), b"default", SND_SEQ_OPEN_DUPLEX, SND_SEQ_NONBLOCK
        )
        if result < 0:
            print(
                f"Error opening ALSA sequencer: {self.alsa_strerror(result)}",
                file=sys.stderr,
            )
            return False
        self.seq = seq_ptr

        alsalib.snd_seq_set_client_name(self.seq, b"py-alsa-ctypes-manager")

        input_port = alsalib.snd_seq_create_simple_port(
            self.seq,
            b"input",
            SND_SEQ_PORT_CAP_WRITE | SND_SEQ_PORT_CAP_SUBS_WRITE,
            SND_SEQ_PORT_TYPE_APPLICATION,
        )
        if input_port < 0:
            print(
                f"Error creating input port: {self.alsa_strerror(input_port)}",
                file=sys.stderr,
            )
            self.stop()
            return False

        connect_result = alsalib.snd_seq_connect_from(self.seq, input_port, 0, 1)
        if connect_result < 0:
            print(
                f"Could not connect from announce port: {self.alsa_strerror(connect_result)}",
                file=sys.stderr,
            )
            self.stop()
            return False
        print("Successfully connected to announce port for events.")

        poll_count = alsalib.snd_seq_poll_descriptors_count(self.seq, select.POLLIN)

        class pollfd(ctypes.Structure):
            _fields_ = [
                ("fd", ctypes.c_int),
                ("events", ctypes.c_short),
                ("revents", ctypes.c_short),
            ]

        self.poll_fds = (pollfd * poll_count)()
        alsalib.snd_seq_poll_descriptors(
            self.seq, ctypes.byref(self.poll_fds), poll_count, select.POLLIN
        )

        self.poller = select.poll()
        for pfd in self.poll_fds:
            self.poller.register(pfd.fd, select.POLLIN)

        return True

    def stop(self):
        """Closes the ALSA sequencer handle."""
        print("Exiting ALSA connection manager.")
        if self.seq:
            alsalib.snd_seq_close(self.seq)
            self.seq = None

    def run(self):
        """Main event loop."""
        if not self.start():
            sys.exit(1)

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        try:
            self.reconcile_connections()
            print(
                "\n--- Initial setup complete. Waiting for ALSA events... (Press Ctrl+C to exit) ---"
            )

            while self.running:
                if self.poller.poll(1000):  # 1 second timeout
                    event_ptr = ctypes.POINTER(snd_seq_event)()
                    reconciliation_needed = False
                    while (
                        alsalib.snd_seq_event_input(self.seq, ctypes.byref(event_ptr))
                        >= 0
                    ):
                        event = event_ptr.contents
                        if event and event.type in RELEVANT_EVENTS:
                            reconciliation_needed = True

                    if reconciliation_needed:
                        print("ALSA Event detected, triggering reconciliation.")
                        self.reconcile_connections()
        finally:
            self.stop()

    def signal_handler(self, sig, frame):
        """Handles signals and sets the running flag to false."""
        print("\nSignal received, shutting down...")
        self.running = False

    def get_current_state(self) -> Tuple[Set[str], Set[Tuple[str, str]]]:
        """
        Gets the current state of the ALSA sequencer.
        Returns (all_ports, all_connections)
        """
        if not self.seq:
            return set(), set()

        available_ports, connections = set(), set()
        client_ports = {}  # { client_id: { port_id: "Full Port String" } }

        cinfo_ptr = snd_seq_client_info_t()
        pinfo_ptr = snd_seq_port_info_t()
        alsalib.snd_seq_client_info_malloc(ctypes.byref(cinfo_ptr))
        alsalib.snd_seq_port_info_malloc(ctypes.byref(pinfo_ptr))

        alsalib.snd_seq_client_info_set_client(cinfo_ptr, -1)
        while alsalib.snd_seq_query_next_client(self.seq, cinfo_ptr) >= 0:
            client_id = alsalib.snd_seq_client_info_get_client(cinfo_ptr)
            client_name = alsalib.snd_seq_client_info_get_name(cinfo_ptr).decode(
                "utf-8"
            )
            client_ports[client_id] = {}

            alsalib.snd_seq_port_info_set_client(pinfo_ptr, client_id)
            alsalib.snd_seq_port_info_set_port(pinfo_ptr, -1)
            while alsalib.snd_seq_query_next_port(self.seq, pinfo_ptr) >= 0:
                addr = alsalib.snd_seq_port_info_get_addr(pinfo_ptr).contents
                port_name = alsalib.snd_seq_port_info_get_name(pinfo_ptr).decode(
                    "utf-8"
                )
                full_port_str = f"{client_name}:{port_name}"
                available_ports.add(full_port_str)
                client_ports[addr.client][addr.port] = full_port_str

        for client_id, ports in client_ports.items():
            for port_id, source_full_str in ports.items():
                alsalib.snd_seq_get_any_port_info(
                    self.seq, client_id, port_id, pinfo_ptr
                )
                caps = alsalib.snd_seq_port_info_get_capability(pinfo_ptr)

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

                    while (
                        alsalib.snd_seq_query_port_subscribers(self.seq, query_ptr) >= 0
                    ):
                        sub_addr = alsalib.snd_seq_query_subscribe_get_addr(
                            query_ptr
                        ).contents
                        try:
                            dest_full_str = client_ports[sub_addr.client][sub_addr.port]
                            connections.add((source_full_str, dest_full_str))
                        except KeyError:
                            pass
                        index = alsalib.snd_seq_query_subscribe_get_index(query_ptr)
                        alsalib.snd_seq_query_subscribe_set_index(query_ptr, index + 1)

                    alsalib.snd_seq_query_subscribe_free(query_ptr)

        alsalib.snd_seq_client_info_free(cinfo_ptr)
        alsalib.snd_seq_port_info_free(pinfo_ptr)
        return available_ports, connections

    def debug_port_capabilities(self, client_id: int, port_id: int) -> str:
        """Returns a string describing the capabilities of a port for debugging."""
        if not self.seq:
            return "sequencer not available"

        pinfo_ptr = snd_seq_port_info_t()
        alsalib.snd_seq_port_info_malloc(ctypes.byref(pinfo_ptr))

        if (
            alsalib.snd_seq_get_any_port_info(self.seq, client_id, port_id, pinfo_ptr)
            < 0
        ):
            alsalib.snd_seq_port_info_free(pinfo_ptr)
            return "cannot get port info"

        caps = alsalib.snd_seq_port_info_get_capability(pinfo_ptr)
        direction = alsalib.snd_seq_port_info_get_direction(pinfo_ptr)

        cap_strings = []
        if caps & SND_SEQ_PORT_CAP_READ:
            cap_strings.append("READ")
        if caps & SND_SEQ_PORT_CAP_SUBS_READ:
            cap_strings.append("SUBS_READ")
        if caps & SND_SEQ_PORT_CAP_WRITE:
            cap_strings.append("WRITE")
        if caps & SND_SEQ_PORT_CAP_SUBS_WRITE:
            cap_strings.append("SUBS_WRITE")

        dir_string = "UNKNOWN"
        if direction == SND_SEQ_PORT_DIR_INPUT:
            dir_string = "INPUT"
        elif direction == SND_SEQ_PORT_DIR_OUTPUT:
            dir_string = "OUTPUT"
        elif direction == (SND_SEQ_PORT_DIR_INPUT | SND_SEQ_PORT_DIR_OUTPUT):
            dir_string = "DUPLEX"

        alsalib.snd_seq_port_info_free(pinfo_ptr)
        return f"caps=0x{caps:x} [{', '.join(cap_strings)}], dir=[{dir_string}]"

    def connect_alsa_ports(
        self, source_str: str, dest_str: str, sender: snd_seq_addr, dest: snd_seq_addr
    ) -> bool:
        """Connects two ALSA ports using subscription mechanism."""
        if not self.seq:
            return False

        print(
            f"  [DEBUG] Source '{source_str}': {self.debug_port_capabilities(sender.client, sender.port)}"
        )
        print(
            f"  [DEBUG] Dest '{dest_str}': {self.debug_port_capabilities(dest.client, dest.port)}"
        )

        sub_ptr = snd_seq_port_subscribe_t()
        alsalib.snd_seq_port_subscribe_malloc(ctypes.byref(sub_ptr))
        alsalib.snd_seq_port_subscribe_set_sender(sub_ptr, ctypes.byref(sender))
        alsalib.snd_seq_port_subscribe_set_dest(sub_ptr, ctypes.byref(dest))

        if alsalib.snd_seq_get_port_subscription(self.seq, sub_ptr) == 0:
            print(f"  [OK] Connection already exists: {source_str} -> {dest_str}")
            alsalib.snd_seq_port_subscribe_free(sub_ptr)
            return True

        result = alsalib.snd_seq_subscribe_port(self.seq, sub_ptr)
        success = result == 0
        alsalib.snd_seq_port_subscribe_free(sub_ptr)

        if success:
            print(f"  [OK] Connected: {source_str} -> {dest_str}")
        else:
            print(
                f"  [ERROR] Failed to connect {source_str} -> {dest_str}: {self.alsa_strerror(result)}",
                file=sys.stderr,
            )

        return success

    def list_available_ports(self):
        """Lists all available MIDI ports for debugging."""
        print("\n--- Available MIDI Ports ---")
        available_ports, _ = self.get_current_state()

        if not available_ports:
            print("  No ports available")
            return

        cinfo_ptr = snd_seq_client_info_t()
        pinfo_ptr = snd_seq_port_info_t()
        alsalib.snd_seq_client_info_malloc(ctypes.byref(cinfo_ptr))
        alsalib.snd_seq_port_info_malloc(ctypes.byref(pinfo_ptr))

        alsalib.snd_seq_client_info_set_client(cinfo_ptr, -1)
        while alsalib.snd_seq_query_next_client(self.seq, cinfo_ptr) >= 0:
            client_id = alsalib.snd_seq_client_info_get_client(cinfo_ptr)
            client_name = alsalib.snd_seq_client_info_get_name(cinfo_ptr).decode(
                "utf-8"
            )

            alsalib.snd_seq_port_info_set_client(pinfo_ptr, client_id)
            alsalib.snd_seq_port_info_set_port(pinfo_ptr, -1)
            while alsalib.snd_seq_query_next_port(self.seq, pinfo_ptr) >= 0:
                addr = alsalib.snd_seq_port_info_get_addr(pinfo_ptr).contents
                port_name = alsalib.snd_seq_port_info_get_name(pinfo_ptr).decode(
                    "utf-8"
                )
                caps = alsalib.snd_seq_port_info_get_capability(pinfo_ptr)

                cap_str = []
                if caps & SND_SEQ_PORT_CAP_READ:
                    cap_str.append("READ")
                if caps & SND_SEQ_PORT_CAP_SUBS_READ:
                    cap_str.append("SUBS_READ")
                if caps & SND_SEQ_PORT_CAP_WRITE:
                    cap_str.append("WRITE")
                if caps & SND_SEQ_PORT_CAP_SUBS_WRITE:
                    cap_str.append("SUBS_WRITE")

                full_port_str = f"{client_name}:{port_name}"
                print(
                    f"  {addr.client:3d}:{addr.port:<2d} {full_port_str:<40} [{', '.join(cap_str)}]"
                )

        alsalib.snd_seq_client_info_free(cinfo_ptr)
        alsalib.snd_seq_port_info_free(pinfo_ptr)

    def get_port_map(self):
        """
        Builds a map of port strings to their client/port IDs.
        Handles arbitrary combinations of names and IDs:
        - "ClientName:PortName"
        - "ClientID:PortID"
        - "ClientName:PortID"
        - "ClientID:PortName"
        """
        if not self.seq:
            return {}

        # Build comprehensive mapping structures
        client_by_id = {}  # {client_id: client_name}
        client_by_name = {}  # {client_name: client_id}
        port_by_client_port_id = {}  # {(client_id, port_id): port_name}
        port_by_client_name = {}  # {(client_name, port_name): (client_id, port_id)}

        cinfo_ptr = snd_seq_client_info_t()
        pinfo_ptr = snd_seq_port_info_t()
        alsalib.snd_seq_client_info_malloc(ctypes.byref(cinfo_ptr))
        alsalib.snd_seq_port_info_malloc(ctypes.byref(pinfo_ptr))

        alsalib.snd_seq_client_info_set_client(cinfo_ptr, -1)
        while alsalib.snd_seq_query_next_client(self.seq, cinfo_ptr) >= 0:
            client_id = alsalib.snd_seq_client_info_get_client(cinfo_ptr)
            client_name = alsalib.snd_seq_client_info_get_name(cinfo_ptr).decode(
                "utf-8"
            )

            client_by_id[client_id] = client_name
            client_by_name[client_name] = client_id

            alsalib.snd_seq_port_info_set_client(pinfo_ptr, client_id)
            alsalib.snd_seq_port_info_set_port(pinfo_ptr, -1)
            while alsalib.snd_seq_query_next_port(self.seq, pinfo_ptr) >= 0:
                addr = alsalib.snd_seq_port_info_get_addr(pinfo_ptr).contents
                port_name = alsalib.snd_seq_port_info_get_name(pinfo_ptr).decode(
                    "utf-8"
                )

                # Store bidirectional mappings
                port_by_client_port_id[(addr.client, addr.port)] = port_name
                port_by_client_name[(client_name, port_name)] = (addr.client, addr.port)

        alsalib.snd_seq_client_info_free(cinfo_ptr)
        alsalib.snd_seq_port_info_free(pinfo_ptr)

        # Build final port map with all possible combinations
        port_map = {}

        # Add basic mappings
        for (client_id, port_id), port_name in port_by_client_port_id.items():
            client_name = client_by_id[client_id]
            # Full name mapping
            port_map[f"{client_name}:{port_name}"] = (client_id, port_id)
            # Full ID mapping
            port_map[f"{client_id}:{port_id}"] = (client_id, port_id)

        # Add mixed mappings
        for (client_name, port_name), (
            client_id,
            port_id,
        ) in port_by_client_name.items():
            # Client name + port ID
            port_map[f"{client_name}:{port_id}"] = (client_id, port_id)
            # Client ID + port name
            port_map[f"{client_id}:{port_name}"] = (client_id, port_id)

        return port_map

    def reconcile_connections(self):
        """Compares the desired state with the current state and makes connections."""
        print("\n--- Reconciling ALSA MIDI Connections ---")
        port_map = self.get_port_map()
        _, current_connections = self.get_current_state()

        if not port_map:
            print("  [WARN] No ALSA MIDI ports available.")
            self.list_available_ports()
            return

        print(f"Found {len(port_map)} available port addresses")
        print(f"Found {len(current_connections)} existing connections")

        for source_str, dest_str in self.desired_connections:
            if (source_str, dest_str) in current_connections:
                print(f"  [OK] Connection already exists: {source_str} -> {dest_str}")
                continue

            source_addr_tuple = port_map.get(source_str)
            if not source_addr_tuple:
                print(f"  [WARN] Source port not available: {source_str}")
                continue

            dest_addr_tuple = port_map.get(dest_str)
            if not dest_addr_tuple:
                print(f"  [WARN] Destination port not available: {dest_str}")
                continue

            print("  [!] Missing connection detected. Attempting to connect...")
            sender = snd_seq_addr(
                client=source_addr_tuple[0], port=source_addr_tuple[1]
            )
            dest = snd_seq_addr(client=dest_addr_tuple[0], port=dest_addr_tuple[1])
            self.connect_alsa_ports(source_str, dest_str, sender, dest)

        if len(self.desired_connections) > 0 and not any(
            source in port_map and dest in port_map
            for source, dest in self.desired_connections
        ):
            self.list_available_ports()

    def alsa_strerror(self, error_code: int) -> str:
        """Converts ALSA error code to human-readable string."""
        error_str = alsalib.snd_strerror(error_code)
        return (
            error_str.decode("utf-8")
            if error_str
            else f"Unknown error code {error_code}"
        )


# --- Main Application ---
def main():
    """Initializes and runs the ALSA connection manager."""
    manager = AlsaManager(DESIRED_CONNECTIONS)
    manager.run()


if __name__ == "__main__":
    main()
