#!/usr/bin/env python
"""
patchrrr.py – unified ALSA MIDI + JACK audio connection manager
"""

import ctypes
import ctypes.util
import queue
import signal
import sys
import threading
from typing import Set, Tuple

# ---------------------------------------------------------------------------
# CONFIGURATION – two independent lists
# ---------------------------------------------------------------------------
ALSA_DESIRED_CONNECTIONS = [
    # Add your ALSA MIDI connections here.
    # Examples:
    # ("Midi Through:Midi Through Port-0", "Pure Data:Pure Data Midi-In 2"),
    # ("Pure Data:2", "14:Midi Through Port-0"),
    # ("20:0", "128:0"),
]

JACK_DESIRED_CONNECTIONS = [
    ("pure_data:output_1", "system:playback_9"),
    ("pure_data:output_2", "system:playback_10"),
]

CLIENT_NAME = "patchrrr"

# ---------------------------------------------------------------------------
# GLOBALS for main-thread coordination
# ---------------------------------------------------------------------------
main_event_queue = queue.Queue()
running = True


# ###########################################################################
# ALSA SECTION – copied verbatim from alsa.py with minimal class wrapper edits
# ###########################################################################

# --- ctypes ALSA Library Definitions -----------------------------------------

libasound_path = ctypes.util.find_library("asound")
if not libasound_path:
    print("ALSA library (libasound) not found.", file=sys.stderr)
    sys.exit(1)
try:
    alsalib = ctypes.CDLL(libasound_path)
except OSError as e:
    print(f"Error loading ALSA library: {e}", file=sys.stderr)
    sys.exit(1)

# Basic ALSA Types and Structures
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
        ("time", ctypes.c_void_p),
        ("source", snd_seq_addr),
        ("dest", snd_seq_addr),
        ("data", ctypes.c_void_p),
    ]


# ALSA Constants
SND_SEQ_OPEN_DUPLEX = 2
SND_SEQ_NONBLOCK = 1
SND_SEQ_PORT_CAP_READ = 1 << 0
SND_SEQ_PORT_CAP_WRITE = 1 << 1
SND_SEQ_PORT_CAP_SUBS_READ = 1 << 5
SND_SEQ_PORT_CAP_SUBS_WRITE = 1 << 6
SND_SEQ_QUERY_SUBS_READ = 1

SND_SEQ_PORT_TYPE_APPLICATION = 1

RELEVANT_EVENTS = {60, 61, 62, 63, 64, 65, 66, 67}

SND_SEQ_PORT_DIR_INPUT = 1
SND_SEQ_PORT_DIR_OUTPUT = 2

# --- ctypes function prototypes for ALSA ------------------------------------
SND_ERROR_HANDLER_T = ctypes.CFUNCTYPE(
    None, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p
)


def null_error_handler(file, line, function, err, fmt):
    pass


alsalib.snd_lib_error_set_handler.argtypes = [SND_ERROR_HANDLER_T]
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
alsalib.snd_seq_create_simple_port.argtypes = [
    snd_seq_t,
    ctypes.c_char_p,
    ctypes.c_uint,
    ctypes.c_uint,
]
alsalib.snd_seq_create_simple_port.restype = ctypes.c_int
alsalib.snd_seq_poll_descriptors_count.argtypes = [snd_seq_t, ctypes.c_short]
alsalib.snd_seq_poll_descriptors.argtypes = [
    snd_seq_t,
    ctypes.c_void_p,
    ctypes.c_uint,
    ctypes.c_short,
]
alsalib.snd_seq_event_input.argtypes = [
    snd_seq_t,
    ctypes.POINTER(ctypes.POINTER(snd_seq_event)),
]
alsalib.snd_seq_event_input.restype = ctypes.c_int
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
alsalib.snd_seq_connect_from.argtypes = [
    snd_seq_t,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
]
alsalib.snd_seq_connect_from.restype = ctypes.c_int
alsalib.snd_seq_get_port_subscription.argtypes = [
    snd_seq_t,
    snd_seq_port_subscribe_t,
]
alsalib.snd_seq_get_port_subscription.restype = ctypes.c_int
alsalib.snd_strerror.argtypes = [ctypes.c_int]
alsalib.snd_strerror.restype = ctypes.c_char_p


class AlsaManager:
    """ALSA MIDI connection manager."""

    def __init__(self, desired_connections):
        self.desired_connections = desired_connections
        self.seq = None
        self.event_queue = queue.Queue()
        self.event_thread = None

        null_handler = SND_ERROR_HANDLER_T(null_error_handler)
        alsalib.snd_lib_error_set_handler(null_handler)

    # -----------------------------------------------------------------------
    # The remainder of AlsaManager is identical to alsa.py except that every
    # reconcile_connections() call publishes "reconcile_alsa" into main_event_queue
    # instead of calling reconcile_connections() directly.
    # -----------------------------------------------------------------------

    def start(self):
        seq_ptr = snd_seq_t()
        result = alsalib.snd_seq_open(
            ctypes.byref(seq_ptr), b"default", SND_SEQ_OPEN_DUPLEX, 0
        )
        if result < 0:
            print(
                f"Error opening ALSA sequencer: {self.alsa_strerror(result)}",
                file=sys.stderr,
            )
            return False
        self.seq = seq_ptr
        alsalib.snd_seq_set_client_name(self.seq, CLIENT_NAME.encode())
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
                f"Could not connect from announce port:{self.alsa_strerror(connect_result)}",
                file=sys.stderr,
            )
            self.stop()
            return False
        print("Successfully connected to announce port for events.")
        return True

    def stop(self):
        print("Exiting ALSA connection manager.")
        if self.seq:
            alsalib.snd_seq_close(self.seq)
            self.seq = None

    def run(self):
        if not self.start():
            sys.exit(1)
        self.reconcile_connections()
        print(
            "\n--- Initial ALSA setup complete. Waiting for events... (Press Ctrl+C to exit) ---"
        )
        self.event_thread = threading.Thread(target=self._event_reader, daemon=True)
        self.event_thread.start()

    def _event_reader(self):
        while running:
            try:
                event_ptr = ctypes.POINTER(snd_seq_event)()
                if alsalib.snd_seq_event_input(self.seq, ctypes.byref(event_ptr)) >= 0:
                    event = event_ptr.contents
                    if event and event.type in RELEVANT_EVENTS:
                        main_event_queue.put("reconcile_alsa")
            except Exception as e:
                if running:
                    print(f"Error in ALSA event reader: {e}", file=sys.stderr)
                break

    # -----------------------------------------------------------------------
    # All other methods from alsa.py follow verbatim (get_current_state, etc.)
    # -----------------------------------------------------------------------
    def get_current_state(self) -> Tuple[Set[str], Set[Tuple[str, str]]]:
        if not self.seq:
            return set(), set()
        available_ports, connections = set(), set()
        client_ports = {}

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

    def reconcile_connections(self):
        print("\n--- Reconciling ALSA MIDI Connections ---")
        port_map = self.get_port_map()
        _, current_connections = self.get_current_state()
        if not port_map:
            print("  [WARN] No ALSA MIDI ports available.")
            self.list_available_ports()
            return
        for source_str, dest_str in self.desired_connections:
            if (source_str, dest_str) in current_connections:
                print(f"  [OK] Connection already exists: {source_str} ->{dest_str}")
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

    def connect_alsa_ports(
        self, source_str: str, dest_str: str, sender: snd_seq_addr, dest: snd_seq_addr
    ) -> bool:
        if not self.seq:
            return False
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

    def get_port_map(self):
        if not self.seq:
            return {}
        client_by_id = {}
        client_by_name = {}
        port_by_client_port_id = {}
        port_by_client_name = {}
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
                port_by_client_port_id[(addr.client, addr.port)] = port_name
                port_by_client_name[(client_name, port_name)] = (
                    addr.client,
                    addr.port,
                )
        alsalib.snd_seq_client_info_free(cinfo_ptr)
        alsalib.snd_seq_port_info_free(pinfo_ptr)
        port_map = {}
        for (client_id, port_id), port_name in port_by_client_port_id.items():
            client_name = client_by_id[client_id]
            port_map[f"{client_name}:{port_name}"] = (client_id, port_id)
            port_map[f"{client_id}:{port_id}"] = (client_id, port_id)
        for (client_name, port_name), (
            client_id,
            port_id,
        ) in port_by_client_name.items():
            port_map[f"{client_name}:{port_id}"] = (client_id, port_id)
            port_map[f"{client_id}:{port_name}"] = (client_id, port_id)
        return port_map

    def list_available_ports(self):
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
                    f"  {addr.client:3d}:{addr.port:<2d} {full_port_str:<40} [{','.join(cap_str)}]"
                )
        alsalib.snd_seq_client_info_free(cinfo_ptr)
        alsalib.snd_seq_port_info_free(pinfo_ptr)

    def alsa_strerror(self, error_code: int) -> str:
        error_str = alsalib.snd_strerror(error_code)
        return (
            error_str.decode("utf-8")
            if error_str
            else f"Unknown error code {error_code}"
        )


# ###########################################################################
# JACK SECTION – refactored from jack.py into JackManager class
# ###########################################################################

# --- ctypes JACK Library Definitions ----------------------------------------

libjack_path = ctypes.util.find_library("jack")
if not libjack_path:
    print("JACK library not found. Please install it.", file=sys.stderr)
    sys.exit(1)
try:
    jacklib = ctypes.CDLL(libjack_path)
except OSError as e:
    print(f"Error loading JACK library: {e}", file=sys.stderr)
    sys.exit(1)

jack_port_id_t = ctypes.c_uint32
jack_uuid_t = ctypes.c_uint64
jack_client_t = ctypes.c_void_p
jack_port_t = ctypes.c_void_p


class JackOptions:
    JackNullOption = 0x00
    JackNoStartServer = 0x01


class JackStatus:
    JackServerFailed = 0x10


ClientCallback = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p)
PortCallback = ctypes.CFUNCTYPE(None, jack_port_id_t, ctypes.c_int, ctypes.c_void_p)
GraphCallback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)

jacklib.jack_client_open.argtypes = [
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int),
]
jacklib.jack_client_open.restype = jack_client_t
jacklib.jack_client_close.argtypes = [jack_client_t]
jacklib.jack_activate.argtypes = [jack_client_t]

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


class JackManager:
    """JACK audio connection manager."""

    def __init__(self, desired_connections):
        self.desired_connections = desired_connections
        self.client = None
        self.event_queue = queue.Queue()
        self.c_client_callback = None
        self.c_port_callback = None
        self.c_graph_callback = None

    # -----------------------------------------------------------------------
    # All former module-level jack functions are now instance methods
    # -----------------------------------------------------------------------
    def start(self):
        status = ctypes.c_int()
        client_name = CLIENT_NAME
        self.client = jacklib.jack_client_open(
            client_name.encode(), JackOptions.JackNoStartServer, ctypes.byref(status)
        )
        if not self.client:
            print("Could not connect to JACK server. Is it running?", file=sys.stderr)
            if status.value & JackStatus.JackServerFailed:
                print("Unable to connect to JACK server", file=sys.stderr)
            return False

        # Keep callback refs alive
        self.c_client_callback = ClientCallback(self._client_callback)
        self.c_port_callback = PortCallback(self._port_callback)
        self.c_graph_callback = GraphCallback(self._graph_callback)

        jacklib.jack_set_client_registration_callback(
            self.client, self.c_client_callback, None
        )
        jacklib.jack_set_port_registration_callback(
            self.client, self.c_port_callback, None
        )
        jacklib.jack_set_graph_order_callback(self.client, self.c_graph_callback, None)

        if jacklib.jack_activate(self.client) != 0:
            print("Cannot activate JACK client.", file=sys.stderr)
            jacklib.jack_client_close(self.client)
            return False
        return True

    def stop(self):
        print("Exiting JACK connection manager.")
        if self.client:
            jacklib.jack_client_close(self.client)
            self.client = None

    def run(self):
        if not self.start():
            sys.exit(1)
        self.reconcile_connections()
        print(
            "\n--- Initial JACK setup complete. Waiting for events... (Press Ctrl+C to exit) ---"
        )
        while running:
            try:
                event = self.event_queue.get(timeout=1.0)
                if event == "reconcile":
                    self.reconcile_connections()
            except queue.Empty:
                pass

    # -----------------------------------------------------------------------
    # Callbacks (internal)
    # -----------------------------------------------------------------------
    def _client_callback(self, client_name_ptr, registered, arg):
        client_name = client_name_ptr.decode()
        status = "registered" if registered else "unregistered"
        print(f"\nJACK Event: Client '{client_name}' {status}")
        if client_name != CLIENT_NAME:
            main_event_queue.put("reconcile_jack")

    def _port_callback(self, port_id, registered, arg):
        status = "registered" if registered else "unregistered"
        print(f"\nJACK Event: A port was {status}")
        main_event_queue.put("reconcile_jack")

    def _graph_callback(self, arg) -> int:
        print("\nJACK Event: Graph order changed")
        main_event_queue.put("reconcile_jack")
        return 0

    # -----------------------------------------------------------------------
    # Utility methods – direct translation of former jack.py functions
    # -----------------------------------------------------------------------
    def get_jack_ports(self) -> Set[str]:
        if not self.client:
            return set()
        ports_ptr = jacklib.jack_get_ports(self.client, None, None, 0)
        if not ports_ptr:
            return set()
        ports = set()
        i = 0
        while ports_ptr[i]:
            ports.add(ports_ptr[i].decode("utf-8"))
            i += 1
        jacklib.jack_free(ports_ptr)
        return ports

    def get_current_connections(self) -> Set[Tuple[str, str]]:
        if not self.client:
            return set()
        connections = set()
        all_ports = self.get_jack_ports()
        for source_port_name in all_ports:
            source_port = jacklib.jack_port_by_name(
                self.client, source_port_name.encode("utf-8")
            )
            if not source_port:
                continue
            connections_ptr = jacklib.jack_port_get_all_connections(
                self.client, source_port
            )
            if not connections_ptr:
                continue
            i = 0
            while connections_ptr[i]:
                dest_port_name = connections_ptr[i].decode("utf-8")
                connections.add((source_port_name, dest_port_name))
                i += 1
            jacklib.jack_free(connections_ptr)
        return connections

    def connect_jack_ports(self, source_port: str, destination_port: str) -> bool:
        if not self.client:
            return False
        if (
            jacklib.jack_connect(
                self.client,
                source_port.encode("utf-8"),
                destination_port.encode("utf-8"),
            )
            == 0
        ):
            print(f"  [OK] Ensuring connection: {source_port} -> {destination_port}")
            return True
        return False

    def reconcile_connections(self):
        print("\n--- Reconciling JACK Connections ---")
        available_ports = self.get_jack_ports()
        current_connections = self.get_current_connections()
        if not available_ports:
            print("  [WARN] JACK server not running or no ports available.")
            return
        for source, dest in self.desired_connections:
            if (source, dest) in current_connections:
                continue
            if source in available_ports and dest in available_ports:
                print("  [!] Missing connection detected. Restoring...")
                self.connect_jack_ports(source, dest)


# ###########################################################################
# MAIN MANAGER CLASS
# ###########################################################################
class PatchrrrManager:
    """Unified ALSA MIDI + JACK audio connection manager."""
    
    def __init__(self, alsa_connections=None, jack_connections=None):
        """
        Initialize the manager with desired connections.
        
        Args:
            alsa_connections: List of (source, dest) tuples for ALSA MIDI
            jack_connections: List of (source, dest) tuples for JACK audio
        """
        self.alsa_connections = alsa_connections or []
        self.jack_connections = jack_connections or []
        self.running = True
        self.alsa_mgr = None
        self.jack_mgr = None
        
    def signal_handler(self, sig, frame):
        """Handle shutdown signals."""
        print("\nSignal received, shutting down...")
        self.running = False
        
    def start(self):
        """Start all managers and begin monitoring."""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.alsa_mgr = AlsaManager(self.alsa_connections)
        self.jack_mgr = JackManager(self.jack_connections)
        
        # Start ALSA in its own thread because it uses blocking reads
        alsa_thread = threading.Thread(target=self.alsa_mgr.run, daemon=True)
        alsa_thread.start()
        
        # Start JACK in its own thread for symmetry
        jack_thread = threading.Thread(target=self.jack_mgr.run, daemon=True)
        jack_thread.start()
        
        # Central dispatcher loop
        try:
            while self.running:
                try:
                    event = main_event_queue.get(timeout=1.0)
                    if event == "reconcile_alsa":
                        self.alsa_mgr.reconcile_connections()
                    elif event == "reconcile_jack":
                        self.jack_mgr.reconcile_connections()
                except queue.Empty:
                    pass
        finally:
            self.stop()
            print("\nAll managers shut down. Goodbye!")
            
    def stop(self):
        """Stop all managers."""
        if self.alsa_mgr:
            self.alsa_mgr.stop()
        if self.jack_mgr:
            self.jack_mgr.stop()


# ###########################################################################
# MAIN (for backward compatibility)
# ###########################################################################
def signal_handler(sig, frame):
    global running
    print("\nSignal received, shutting down...")
    running = False


def main():
    """Legacy main function for backward compatibility."""
    manager = PatchrrrManager(ALSA_DESIRED_CONNECTIONS, JACK_DESIRED_CONNECTIONS)
    manager.start()


if __name__ == "__main__":
    main()
