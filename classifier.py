import argparse
import csv
import ipaddress
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Tuple
import numpy as np
from itertools import groupby
from datetime import datetime

DISCORD_NET = ipaddress.ip_network("162.159.128.0/17")
MEDIA_NETS = [
    ipaddress.ip_network("104.0.0.0/8"),
    ipaddress.ip_network("34.0.0.0/10"),
    ipaddress.ip_network("172.253.0.0/16"),
]
GOOGLE_NET = ipaddress.ip_network("142.250.0.0/15")

DISCORD_AUTH_DOMAINS = [
    "discord.com", "discordapp.com", "gateway.discord.gg",
    "updates.discord.com", "status.discord.com",
]

DISCORD_SNI_SUFFIXES = (
    "discord.com", "discord.gg", "discordapp.com",
    "discordapp.net", "discord.media",
)
GOOGLE_SNI_SUFFIXES = (
    "google.com", "googleusercontent.com", "googleapis.com",
    "gstatic.com", "googlevideo.com", "ggpht.com",
)
CLOUDFLARE_SNI_SUFFIXES = ("cloudflare.com", "cloudflare-ech.com",)
CLOUD_SNI_SUFFIXES = GOOGLE_SNI_SUFFIXES + CLOUDFLARE_SNI_SUFFIXES

DEFAULT_WINDOW_SEC = 1.0
SEND_RATIO = 1.4
RECV_RATIO = 1.0 / SEND_RATIO
MIN_WINDOW_PACKETS = 10
MIN_WINDOW_MEDIAN_SIZE = 60


@dataclass
class Packet:
    ts: float
    src: str
    dst: str
    proto: str
    info: str
    length: int
    sni: Optional[str]


@dataclass
class Window:
    start: float
    end: float
    packets: int
    out_cnt: int
    in_cnt: int
    median_size: float
    label: str


@dataclass
class Phase:
    label: str
    start: float
    end: float
    packets: int
    out_cnt: int
    in_cnt: int
    median_size: float


# ─── Сетевые утилиты ──────────────────────────────────────────────────────────

def which_tshark() -> str:
    from shutil import which
    t = which("tshark")
    if not t:
        raise RuntimeError("tshark not found in PATH")
    return t


def is_discord_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in DISCORD_NET
    except ValueError:
        return False


def is_media_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in MEDIA_NETS)
    except ValueError:
        return False


def is_google_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in GOOGLE_NET
    except ValueError:
        return False


def clean_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def host_matches(host: str, suffixes: tuple) -> bool:
    host = clean_host(host)
    if not host:
        return False
    return any(host == s or host.endswith("." + s) or host.endswith(s) for s in suffixes)


def is_cloud_sni(host: str) -> bool:
    return host_matches(host, CLOUD_SNI_SUFFIXES)


def is_discord_sni(host: str) -> bool:
    return host_matches(host, DISCORD_SNI_SUFFIXES)


def is_hcaptcha_traffic(p: Packet) -> bool:
    if not p:
        return False
    info_lower = (p.info or "").lower()
    sni_lower = (p.sni or "").lower()
    kws = [
        "hcaptcha.com", "api.hcaptcha.com", "imgs3.hcaptcha.com",
        "js.hcaptcha.com", "newassets.hcaptcha.com",
    ]
    return any(k in info_lower for k in kws) or any(k in sni_lower for k in kws)


# ─── Загрузка пакетов ─────────────────────────────────────────────────────────

def load_packets(pcap_path: Path) -> List[Packet]:
    tshark = which_tshark()
    fields = [
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "frame.protocols", "-e", "_ws.col.Info", "-e", "frame.len",
        "-e", "tls.handshake.extensions_server_name",
    ]
    cmd = [tshark, "-r", str(pcap_path), "-Y", "ip", "-T", "fields",
           "-E", "separator=\t"] + fields
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    packets = []
    for row in csv.reader(proc.stdout.splitlines(), delimiter="\t"):
        if len(row) < 6:
            continue
        try:
            packets.append(Packet(
                float(row[0]), row[1], row[2], row[3], row[4],
                int(row[5]) if row[5] else 0,
                row[6] if len(row) > 6 else None,
            ))
        except Exception:
            continue
    packets.sort(key=lambda p: p.ts)
    return packets


def infer_client_ip(packets: List[Packet]) -> Optional[str]:
    counter: Counter = Counter()
    for p in packets:
        if not is_discord_ip(p.src):
            counter[p.src] += 1
        if not is_discord_ip(p.dst):
            counter[p.dst] += 1
    if not counter:
        for p in packets:
            if not is_discord_ip(p.src):
                return p.src
            if not is_discord_ip(p.dst):
                return p.dst
    return counter.most_common(1)[0][0] if counter else None


def format_timestamp(ts: float) -> str:
    if ts is None:
        return "N/A"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def in_any_interval(ts: float, intervals: List[Tuple[float, float]]) -> bool:
    return any(start <= ts <= end for start, end in intervals)

# ─── Классификация регистрации / авторизации ──────────────────────────────────

def is_registration_like(packets: List[Packet]) -> bool:
    dns_discord = sum(
        1 for p in packets
        if "dns" in p.proto.lower()
        and any(dom in (p.info or "").lower() for dom in DISCORD_AUTH_DOMAINS)
    )
    sni_discord = sum(
        1 for p in packets
        if p.sni
        and any(dom in (p.sni or "").lower() for dom in DISCORD_AUTH_DOMAINS)
    )
    discord_count = sum(
        1 for p in packets
        if is_discord_ip(p.src) or is_discord_ip(p.dst)
    )
    if not ((dns_discord >= 1 or sni_discord >= 1) and discord_count >= 30):
        return False

    first_discord_ts = next(
        (p.ts for p in packets if is_discord_ip(p.src) or is_discord_ip(p.dst)),
        None,
    )
    first_media_ts = next(
        (p.ts for p in packets if is_media_ip(p.src) or is_media_ip(p.dst)),
        None,
    )
    if first_discord_ts is not None and first_media_ts is not None:
        if first_media_ts - first_discord_ts < 15.0:
            return False

    return True


def classify_registration(
    packets: List[Packet],
) -> Tuple[str, str, List[Dict], Optional[float], Optional[float]]:
    candidate_times = []
    for p in packets:
        proto = (p.proto or "").lower()
        info = (p.info or "").lower()
        sni = (p.sni or "").lower()
        if "dns" in proto and any(dom in info for dom in DISCORD_AUTH_DOMAINS):
            candidate_times.append(p.ts)
        elif sni and any(dom in sni for dom in DISCORD_AUTH_DOMAINS):
            candidate_times.append(p.ts)

    if not candidate_times:
        return "Unknown", "Нет признаков начала сессии (DNS/SNI)", [], None, None

    candidate_times = sorted(set(candidate_times))
    best = None

    first_packet_ts = packets[0].ts if packets else 0.0

    for first_discord_time in candidate_times:
        if first_discord_time - first_packet_ts > 45.0:
            continue

        discord_after_offset = [
            p for p in packets
            if p.ts >= first_discord_time + 5
            and (is_discord_ip(p.src) or is_discord_ip(p.dst))
        ]
        if not discord_after_offset:
            continue

        burst_start = None
        max_density = 0
        left = 0
        for right in range(len(discord_after_offset)):
            while discord_after_offset[right].ts - discord_after_offset[left].ts > 1.0:
                left += 1
            density = right - left + 1
            if density > max_density:
                max_density = density
                burst_start = discord_after_offset[left].ts
            if max_density > 75:
                break

        phase_end = burst_start if burst_start else (first_discord_time + 60)
        if phase_end <= first_discord_time + 1:
            continue
        if max_density < 25:
            continue

        discord_packets = [
            p for p in packets
            if (is_discord_ip(p.src) or is_discord_ip(p.dst))
            and first_discord_time <= p.ts < phase_end
        ]

        clusters = []
        if discord_packets:
            cur = [discord_packets[0]]
            for p in discord_packets[1:]:
                if p.ts - cur[-1].ts <= 0.25:
                    cur.append(p)
                else:
                    if len(cur) >= 2:
                        clusters.append(cur)
                    cur = [p]
            if len(cur) >= 2:
                clusters.append(cur)

        count = len(clusters)
        has_hcaptcha = any(
            is_hcaptcha_traffic(p)
            for p in packets
            if first_discord_time <= p.ts <= phase_end
        )
        duration = phase_end - first_discord_time

        reg_score = 0
        auth_score = 0

        early_window_end = first_discord_time + 6.0
        late_window_start = first_discord_time + 12.0

        auth_dns_early = sum(
            1 for p in packets
            if p.ts <= early_window_end
            and "dns" in (p.proto or "").lower()
            and any(dom in (p.info or "").lower() for dom in DISCORD_AUTH_DOMAINS)
        )
        auth_sni_count = sum(
            1 for p in packets
            if p.ts <= early_window_end
            and p.sni
            and any(dom in (p.sni or "").lower() for dom in DISCORD_AUTH_DOMAINS)
        )
        early_discord = sum(
            1 for p in packets
            if first_discord_time <= p.ts <= early_window_end
            and (is_discord_ip(p.src) or is_discord_ip(p.dst))
        )
        late_discord = sum(
            1 for p in packets
            if late_window_start <= p.ts <= phase_end
            and (is_discord_ip(p.src) or is_discord_ip(p.dst))
        )
        auth_early_vs_late_ratio = early_discord / max(late_discord, 1)

        if has_hcaptcha:
            reg_score += 3
        if count >= 12:
            reg_score += 2
        if count >= 18:
            reg_score += 1
        if duration >= 18:
            reg_score += 1

        if auth_dns_early >= 1:
            auth_score += 2
        if auth_sni_count >= 2:
            auth_score += 1
        if 5 <= count <= 11:
            auth_score += 2
        if duration <= 22:
            auth_score += 1
        if auth_early_vs_late_ratio >= 1.2:
            auth_score += 1

        if reg_score >= 4 and reg_score >= auth_score + 2:
            scenario = "Registration"
        elif auth_score >= 4 and auth_score >= reg_score + 2:
            scenario = "Authorization"
        else:
            continue

        detail = (
            f"reg_score={reg_score}, auth_score={auth_score}, "
            f"clusters={count}, hcaptcha={int(has_hcaptcha)}"
        )
        gap = abs(reg_score - auth_score)
        total = max(reg_score, auth_score)

        cand = (gap, total, duration, scenario, detail,
                first_discord_time, phase_end, reg_score, auth_score)
        if best is None or (cand[0], cand[1], cand[2]) > (best[0], best[1], best[2]):
            best = cand

    if best is None:
        return "Unknown", "Слабая уверенность", [], None, None

    _, _, _, scenario, detail, first_discord_time, phase_end, _, _ = best
    time_range = (
        f"{format_timestamp(first_discord_time)} – {format_timestamp(phase_end)}"
    )
    client_ip = infer_client_ip(packets) or "-"
    events = [{
        "scenario": scenario,
        "direction": detail,
        "time_range": time_range,
        "src_ip": client_ip,
        "dst_ip": "-",
        "start_ts": first_discord_time,
        "end_ts": phase_end,
    }]
    return scenario, detail, events, first_discord_time, phase_end


# ─── Классификация сообщений ────────────────────────────────────

def classify_message(
    packets: List[Packet],
    client_ip: str,
    occupied_intervals: Optional[List[Tuple[float, float]]] = None,
) -> List[Dict]:
    if occupied_intervals is None:
        occupied_intervals = []

    OCCUPIED_BUFFER = 6.0
    buffered_occupied = [
        (s - OCCUPIED_BUFFER, e + OCCUPIED_BUFFER) for s, e in occupied_intervals
    ]

    def in_occupied(ts: float) -> bool:
        return any(s <= ts <= e for s, e in buffered_occupied)

    discord_pkts = [
        p for p in packets
        if (is_discord_ip(p.src) or is_discord_ip(p.dst))
        and not in_occupied(p.ts)
    ]
    if len(discord_pkts) < 30:
        return []

    clusters = []
    current = [discord_pkts[0]]
    for p in discord_pkts[1:]:
        if p.ts - current[-1].ts <= 0.25:
            current.append(p)
        else:
            if 2 <= len(current) <= 14:
                clusters.append(current)
            current = [p]
    if 2 <= len(current) <= 14:
        clusters.append(current)

    clusters = [cl for cl in clusters if max(p.length for p in cl) >= 80]

    if len(clusters) < 3:
        return []

    span = discord_pkts[-1].ts - discord_pkts[0].ts
    if span < 6.0:
        return []

    msgs = []
    for cl in clusters:
        out_bytes = sum(p.length for p in cl if p.src == client_ip)
        in_bytes  = sum(p.length for p in cl if p.dst == client_ip)
        sizes = [p.length for p in cl]

        if out_bytes > 1.5 * in_bytes:
            direction = "Отправка сообщения"
            src_ip = client_ip
            dst_ip = Counter(p.dst for p in cl if p.dst != client_ip).most_common(1)
            dst_ip = dst_ip[0][0] if dst_ip else (cl[0].dst if cl else "-")

        elif in_bytes > 1.5 * out_bytes:
            if len(cl) <= 3:
                if in_bytes < 80:
                    continue
            else:
                server_substantial = sum(
                    1 for p in cl if p.src != client_ip and p.length > 150
                )
                if server_substantial < 1:
                    continue

            direction = "Приём сообщения"
            src_ip = Counter(p.src for p in cl if p.src != client_ip).most_common(1)
            src_ip = src_ip[0][0] if src_ip else (cl[0].src if cl else "-")
            dst_ip = client_ip
        else:
            continue

        msgs.append({
            "scenario": "Сообщение",
            "direction": direction,
            "time_range": format_timestamp(cl[0].ts),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "med_size": round(sum(sizes) / len(sizes), 1),
            "max_size": max(sizes),
            "pkt_count": len(cl),
            "start_ts": cl[0].ts,
        })

    msgs.sort(key=lambda x: x["start_ts"])

    send_events = [
        (m["start_ts"], m["pkt_count"])
        for m in msgs
        if m["direction"] == "Отправка сообщения"
    ]
    final_msgs = []
    for msg in msgs:
        if msg["direction"] == "Приём сообщения":
            is_echo = False
            for st, sp in send_events:
                time_diff = msg["start_ts"] - st
                if 0 < time_diff <= 2.0 and msg["pkt_count"] <= sp:
                    is_echo = True
                    break
            if is_echo:
                continue
        final_msgs.append(msg)

    return final_msgs

# ─── CDN-детектор ────────

DISCORD_CDN_IPS = {
    "162.159.130.233", "162.159.129.233", "162.159.134.233",
    "162.159.133.233", "162.159.135.233",
}


def is_cdn_discord_ip(ip: str) -> bool:
    if ip in DISCORD_CDN_IPS:
        return True
    if is_discord_ip(ip):
        last_octet = ip.rsplit(".", 1)[-1]
        if last_octet in ("232", "233"):
            return True
    return False


# ─── Поиск файловых передач ───────────────────────────────────────────────────

def find_file_transfers(
    packets: List[Packet],
    src_condition,
    dst_condition,
    min_length: int = 1100,
    min_packets: int = 180,
    min_duration: float = 0.3,
    max_gap: float = 5.0,
):
    candidates = [
        p for p in packets
        if p.length >= min_length
        and src_condition(p.src)
        and dst_condition(p.dst)
    ]
    if len(candidates) < min_packets:
        return [], set()

    transfers = []
    used: set = set()
    current = [candidates[0]]
    curr_indices = [0]

    for i in range(1, len(candidates)):
        p = candidates[i]
        if p.ts - current[-1].ts <= max_gap:
            current.append(p)
            curr_indices.append(i)
        else:
            duration = current[-1].ts - current[0].ts
            if len(current) >= min_packets and duration >= min_duration:
                transfers.append(current)
                used.update(curr_indices)
            current = [p]
            curr_indices = [i]

    duration = current[-1].ts - current[0].ts
    if len(current) >= min_packets and duration >= min_duration:
        transfers.append(current)
        used.update(curr_indices)

    return transfers, used


def classify_file_transfer(
    packets: List[Packet],
    client_ip: str,
    media_segments=None,
    ignore_until: Optional[float] = None,
):
    if media_segments is None:
        media_segments = []

    filtered_packets = packets
    if ignore_until is not None:
        filtered_packets = [p for p in packets if p.ts >= ignore_until + 2.0]

    events = []
    transfer_intervals = []

    google_transfers, _ = find_file_transfers(
        filtered_packets,
        lambda ip: ip == client_ip,
        is_google_ip,
        min_length=800,
        min_packets=150,
        min_duration=0.5,
        max_gap=5.0,
    )
    cdn_transfers, _ = find_file_transfers(
        filtered_packets,
        is_cdn_discord_ip,
        lambda ip: ip == client_ip,
        min_length=950,
        min_packets=60,          
        min_duration=0.4,
        max_gap=4.0,
    )

    UI_LOADING_MAX_START_DELAY = 5.0
    UI_LOADING_MIN_PACKETS = 200

    for burst in google_transfers:
        if ignore_until is not None:
            start_delay = burst[0].ts - ignore_until
            if (start_delay < UI_LOADING_MAX_START_DELAY
                    and len(burst) >= UI_LOADING_MIN_PACKETS):
                continue
        dst_ip = Counter(p.dst for p in burst).most_common(1)[0][0]
        events.append({
            "scenario": "Файл",
            "direction": "Отправка",
            "time_range": format_timestamp(burst[0].ts),
            "src_ip": client_ip,
            "dst_ip": dst_ip,
            "packets": len(burst),
            "start_ts": burst[0].ts,
            "end_ts": burst[-1].ts,
        })
        transfer_intervals.append((burst[0].ts, burst[-1].ts))

    for burst in cdn_transfers:
        if ignore_until is not None:
            start_delay = burst[0].ts - ignore_until
            if start_delay < UI_LOADING_MAX_START_DELAY:
                continue
        in_bytes = sum(p.length for p in burst if p.dst == client_ip)
        out_bytes = sum(p.length for p in burst if p.src == client_ip)

        if in_bytes < 2.5 * max(out_bytes, 1):
            continue
        if max(p.length for p in burst) < 900:   
            continue

        src_ip = Counter(p.src for p in burst).most_common(1)[0][0]
        events.append({
            "scenario": "Файл",
            "direction": "Приём",
            "time_range": format_timestamp(burst[0].ts),
            "src_ip": src_ip,
            "dst_ip": client_ip,
            "packets": len(burst),
            "start_ts": burst[0].ts,
            "end_ts": burst[-1].ts,
        })
        transfer_intervals.append((burst[0].ts, burst[-1].ts))

    return events, transfer_intervals


# ─── Медиасегменты ────────────────────────────────────────────────────────────

def find_media_segments(
    packets: List[Packet],
    gap_threshold: float = 1.0,
    min_duration: float = 2.0,
) -> List[Tuple[float, float]]:
    media = [
        p for p in packets
        if "udp" in p.proto.lower()
        and (is_media_ip(p.src) or is_media_ip(p.dst))
        and p.length >= 140
    ]
    if len(media) < 40:
        return []

    segments = []
    seg_start = media[0].ts
    prev_ts = media[0].ts

    for p in media[1:]:
        if p.ts - prev_ts > gap_threshold:
            if prev_ts - seg_start >= min_duration:
                segments.append((seg_start, prev_ts))
            seg_start = p.ts
        prev_ts = p.ts

    if prev_ts - seg_start >= min_duration:
        segments.append((seg_start, prev_ts))

    return segments


def find_media_window(packets: List[Packet]) -> Tuple[float, float]:
    media = [
        p for p in packets
        if "udp" in p.proto.lower()
        and (is_media_ip(p.src) or is_media_ip(p.dst))
        and p.length >= 140
    ]
    if len(media) < 40:
        return 0.0, 0.0

    control_ts = None
    for p in packets:
        if control_ts is None and (
            "discord.media" in (p.sni or "").lower() or
            "discord.media" in (p.info or "").lower()
        ):
            control_ts = p.ts
            break
    if control_ts is None:
        control_ts = media[0].ts

    relevant_media = [p for p in media if p.ts >= control_ts]
    if not relevant_media:
        return 0.0, 0.0
    return relevant_media[0].ts, relevant_media[-1].ts


# ─── Оконный анализ медиапотока ───────────────────────────────────────────────

def classify_window(out_cnt, in_cnt, median_size, pkt_count) -> str:
    if pkt_count < MIN_WINDOW_PACKETS or median_size < MIN_WINDOW_MEDIAN_SIZE:
        return "noise"
    if out_cnt == 0 and in_cnt == 0:
        return "noise"
    ratio = out_cnt / in_cnt if in_cnt > 0 else float("inf")
    if ratio >= SEND_RATIO:
        return "send"
    if ratio <= RECV_RATIO:
        return "recv"
    return "sim"


def build_windows(
    media_packets: List[Packet], client_ip: str, window_sec: float
) -> List[Window]:
    if not media_packets:
        return []
    start = media_packets[0].ts
    end = media_packets[-1].ts
    windows: List[Window] = []
    i = 0
    n = len(media_packets)
    w_start = start

    while w_start <= end:
        w_end = w_start + window_sec
        chunk = []
        while i < n and media_packets[i].ts < w_end:
            if media_packets[i].ts >= w_start:
                chunk.append(media_packets[i])
            i += 1
        out_cnt = sum(1 for p in chunk if p.src == client_ip)
        in_cnt = sum(1 for p in chunk if p.dst == client_ip)
        med_size = float(np.median([p.length for p in chunk])) if chunk else 0.0
        label = classify_window(out_cnt, in_cnt, med_size, len(chunk))
        windows.append(Window(
            start=w_start, end=w_end, packets=len(chunk),
            out_cnt=out_cnt, in_cnt=in_cnt, median_size=med_size, label=label,
        ))
        w_start = w_end

    return windows


def smooth_labels(windows: List[Window]) -> List[Window]:
    if len(windows) < 3:
        return windows
    labels = [w.label for w in windows]
    for i in range(1, len(labels) - 1):
        if labels[i] == "noise" and labels[i - 1] == labels[i + 1] != "noise":
            labels[i] = labels[i - 1]
    for i in range(1, len(labels) - 1):
        if labels[i - 1] == labels[i + 1] != labels[i] and labels[i] != "noise":
            labels[i] = labels[i - 1]
    return [
        Window(start=w.start, end=w.end, packets=w.packets,
               out_cnt=w.out_cnt, in_cnt=w.in_cnt, median_size=w.median_size, label=lab)
        for w, lab in zip(windows, labels)
    ]


def merge_windows_to_phases(windows: List[Window]) -> List[Phase]:
    phases: List[Phase] = []
    cur: Optional[Phase] = None
    for w in windows:
        if w.label == "noise":
            continue
        if cur is None:
            cur = Phase(label=w.label, start=w.start, end=w.end,
                        packets=w.packets, out_cnt=w.out_cnt, in_cnt=w.in_cnt,
                        median_size=w.median_size)
            continue
        if w.label == cur.label and w.start - cur.end <= 2.0:
            cur.end = w.end
            cur.packets += w.packets
            cur.out_cnt += w.out_cnt
            cur.in_cnt += w.in_cnt
            cur.median_size = (cur.median_size + w.median_size) / 2.0
        else:
            phases.append(cur)
            cur = Phase(label=w.label, start=w.start, end=w.end,
                        packets=w.packets, out_cnt=w.out_cnt, in_cnt=w.in_cnt,
                        median_size=w.median_size)
    if cur is not None:
        phases.append(cur)
    return phases


# ─── Медиа-метрики и классификация типа звонка ────────────────────────────────

def compute_media_metrics(
    packets: List[Packet],
    seg_start: Optional[float] = None,
    seg_end: Optional[float] = None,
) -> Dict:
    if seg_start is None or seg_end is None:
        seg_start, seg_end = find_media_window(packets)

    if seg_start == 0.0 and seg_end == 0.0:
        return {"error": "no media window found"}

    window_packets = [p for p in packets if seg_start <= p.ts <= seg_end]
    media_udp = [
        p for p in window_packets
        if "udp" in p.proto.lower()
        and (is_media_ip(p.src) or is_media_ip(p.dst))
        and p.length >= 140
    ]
    if len(media_udp) < 40:
        return {"error": "insufficient media packets"}

    sizes = [p.length for p in media_udp]
    median_size = float(np.median(sizes))
    max_size = float(max(sizes))
    pkt_std = float(np.std(sizes))
    pkt_p5 = float(np.percentile(sizes, 5))

    outgoing_src = [p.src for p in media_udp if is_media_ip(p.dst)]
    client_ip = Counter(outgoing_src).most_common(1)[0][0] if outgoing_src else None

    media_ips: set = set()
    for p in media_udp:
        if is_media_ip(p.src):
            media_ips.add(p.src)
        if is_media_ip(p.dst):
            media_ips.add(p.dst)
    remote_ips = len(media_ips)

    dst_seq = [p.dst for p in media_udp if is_media_ip(p.dst)]
    dst_runs = [(k, sum(1 for _ in g)) for k, g in groupby(dst_seq)]
    stable_servers = [k for k, cnt in dst_runs if cnt >= 5]
    server_switches = max(0, len(set(stable_servers)) - 1)
    unique_dst = len(set(dst_seq)) if dst_seq else 0
    window_duration = seg_end - seg_start

    phases = []
    if client_ip and len(media_udp) > 50:
        windows = build_windows(media_udp, client_ip, DEFAULT_WINDOW_SEC)
        windows = smooth_labels(windows)
        v3_phases = merge_windows_to_phases(windows)

        for ph in v3_phases:
            if ph.label == "noise":
                continue
            if ph.label == "send":
                typ = "Отправка"
                src_ip = client_ip
                dst_ips = list({
                    p.dst for p in media_udp
                    if ph.start <= p.ts <= ph.end and p.src == client_ip
                })
            elif ph.label == "recv":
                typ = "Принятие"
                src_ips = list({
                    p.src for p in media_udp
                    if ph.start <= p.ts <= ph.end and p.dst == client_ip
                })
                src_ip = ", ".join(src_ips) if src_ips else "media-server"
                dst_ips = [client_ip]
            else:
                typ = "Принятие и отправка одновременно"
                src_ip = client_ip
                dst_ips = list({
                    p.dst for p in media_udp
                    if ph.start <= p.ts <= ph.end and p.src == client_ip
                })

            phases.append({
                "type": typ,
                "start_sec": round(ph.start - seg_start, 2),
                "end_sec": round(ph.end - seg_start, 2),
                "start_ts": ph.start,
                "end_ts": ph.end,
                "src_ip": src_ip,
                "dst_ips": dst_ips if isinstance(dst_ips, list) else [dst_ips],
            })

    phase_labels = [ph["type"] for ph in phases]

    screen_like = (
        (pkt_std > 300 and pkt_p5 < 250 and median_size > 300)
        or (pkt_std > 350 and median_size > 300)
    )

    if screen_like:
        scenario = "Screen Sharing"
        reason = f"screen_like (std={pkt_std:.0f}, p5={pkt_p5:.0f}, phases={len(phase_labels)})"
    elif pkt_std < 120 and median_size < 350:
        scenario = "Audio Call"
        reason = f"аудио (median={median_size:.0f}, std={pkt_std:.0f})"
    elif max_size < 600 and remote_ips <= 1:
        scenario = "Audio Call"
        reason = f"аудио fallback (max={max_size:.0f}, ips={remote_ips})"
    elif max_size > 1100 and remote_ips <= 2 and server_switches == 0:
        scenario = "Video Call"
        reason = f"видео (med={median_size:.0f}, max={max_size:.0f})"
    else:
        scenario = "Video Call"
        reason = f"медиа-трафик (max={max_size:.0f}, ips={remote_ips}, dst={unique_dst})"

    return {
        "scenario": scenario,
        "reason": reason,
        "median_media_size": round(median_size, 1),
        "max_media_size": round(max_size, 1),
        "pkt_std": round(pkt_std, 1),
        "pkt_p5": round(pkt_p5, 1),
        "distinct_media_ips": remote_ips,
        "server_switches": server_switches,
        "window_start": round(seg_start - packets[0].ts, 1) if packets else 0,
        "window_duration": round(window_duration, 1),
        "phases": phases,
        "client_ip": client_ip or "-",
        "first_media_ts": seg_start,
        "server_ips": list({p.dst for p in media_udp} | {p.src for p in media_udp}),
    }


def classify_session(m: Dict) -> Tuple[str, str, List[Dict]]:
    scenario = m.get("scenario", "Video Call")
    detail = m.get("reason", f"медиа-трафик (max {m.get('max_media_size', 0):.1f})")
    phases = m.get("phases", [])
    events = []

    if not phases:
        first_ts = m.get("first_media_ts", 0)
        events.append({
            "scenario": scenario,
            "direction": detail,
            "time_range": format_timestamp(first_ts),
            "src_ip": m.get("client_ip") or "-",
            "dst_ip": "media-server",
        })

    for ph in phases:
        if not isinstance(ph, dict):
            continue
        duration = ph.get("end_ts", 0) - ph.get("start_ts", 0)
        if duration < 0.5:
            continue
        start_time = format_timestamp(ph.get("start_ts", 0))
        end_time = format_timestamp(ph.get("end_ts", 0))
        dst_ip_display = (
            ", ".join(str(ip) for ip in ph.get("dst_ips", []))
            if ph.get("dst_ips") else "media-server"
        )
        events.append({
            "scenario": scenario,
            "direction": ph.get("type", "Неизвестно"),
            "time_range": f"{start_time} – {end_time}",
            "src_ip": ph.get("src_ip") or m.get("client_ip") or "-",
            "dst_ip": dst_ip_display,
            "start_ts": ph.get("start_ts", 0),
            "end_ts": ph.get("end_ts", 0),
        })
    return scenario, detail, events

def is_media_like(packets: List[Packet]) -> bool:
    count = sum(
        1 for p in packets
        if "udp" in p.proto.lower()
        and (is_media_ip(p.src) or is_media_ip(p.dst))
        and p.length >= 120
    )
    return count >= 100


def is_message_like(packets: List[Packet], client_ip: str) -> bool:
    discord_pkts = [p for p in packets if is_discord_ip(p.src) or is_discord_ip(p.dst)]
    if len(discord_pkts) < 30:
        return False

    small_2_3 = 0    
    substantial = 0  
    i = 0
    while i < len(discord_pkts):
        j = i
        while j < len(discord_pkts) and discord_pkts[j].ts - discord_pkts[i].ts <= 0.25:
            j += 1
        cluster = discord_pkts[i:j]
        size = j - i

        if 2 <= size <= 3:
            if max(p.length for p in cluster) >= 80:
                small_2_3 += 1
        elif 4 <= size <= 12 and any(p.length > 200 for p in cluster):
            substantial += 1
        i = j

    return small_2_3 >= 5 or substantial >= 3 or (small_2_3 >= 2 and substantial >= 1)
# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discord Traffic Classifier v3 (multi-scenario)"
    )
    parser.add_argument("path", help="Папка с pcap-файлами или путь к одному файлу")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Сохранить результат в TXT-файл")
    parser.add_argument("--txt", action="store_true",
                        help="Сохранить в discord_full_report.txt")
    args = parser.parse_args()

    path = Path(args.path)
    files = sorted(path.glob("*.pcap*")) if path.is_dir() else [path]

    all_events: List[Dict] = []
    output_path = (
        Path(args.output) if args.output else
        (Path("discord_full_report.txt") if args.txt else None)
    )

    for f in files:
        try:
            packets = load_packets(f)
            if not packets:
                continue

            client_ip = infer_client_ip(packets) or "unknown"
            events: List[Dict] = []
            occupied: List[Tuple[float, float]] = []

            def _ap(src_packets: List[Packet]) -> List[Packet]:
                return [p for p in src_packets if not in_any_interval(p.ts, occupied)]

            # ── Регистрация/Авторизация ──────────────────────────────
            reg_end_time: Optional[float] = None
            if is_registration_like(packets):
                scenario, _, reg_ev, reg_start, reg_end = classify_registration(packets)
                if scenario != "Unknown":
                    events.extend(reg_ev)
                    reg_end_time = reg_end
                if reg_start is not None and reg_end is not None:
                    if scenario == "Authorization":
                        occupied.append((reg_start - 0.5, reg_end + 2.0))
                    else:
                        occupied.append((reg_start - 1.0, reg_end + 3.0))

            an_pkts = _ap(packets)

            # ── Медиа ──────────────────────────────────────────────────
            media_events: List[Dict] = []
            segments: List[Tuple[float, float]] = []
            screen_found = False

            if is_media_like(an_pkts):
                segments = find_media_segments(an_pkts)
                segments_to_try = segments if segments else [(None, None)]

                if segments:
                    occupied.extend(segments)
                    full_media_start = segments[0][0]
                    full_media_end = segments[-1][1]
                    if full_media_end > full_media_start:
                        occupied.append((full_media_start, full_media_end))

                for seg_s, seg_e in segments_to_try:
                    m = compute_media_metrics(an_pkts, seg_s, seg_e)
                    if "error" not in m:
                        _, _, seg_evs = classify_session(m)
                        if any(ev.get("scenario") == "Screen Sharing" for ev in seg_evs):
                            screen_found = True
                        media_events.extend(seg_evs)

                if not screen_found and len(segments_to_try) <= 2:
                    whole_m = compute_media_metrics(an_pkts)
                    if "error" not in whole_m:
                        wss = 0
                        if whole_m.get("distinct_media_ips", 0) >= 4:
                            wss += 2
                        if whole_m.get("server_switches", 0) >= 3:
                            wss += 1
                        if whole_m.get("window_duration", 0) >= 18:
                            wss += 1
                        if whole_m.get("median_media_size", 0) >= 900:
                            wss += 1
                        if wss >= 3:
                            whole_m["scenario"] = "Screen Sharing"
                            _, _, whole_evs = classify_session(whole_m)
                            media_events.extend(whole_evs[:1])

            events.extend(media_events)

            # ── Файловые передачи ──────────────────────────────────────
            an_pkts2 = _ap(packets)
            file_evs, file_intervals = classify_file_transfer(
                an_pkts2, client_ip, ignore_until=reg_end_time
            )
            events.extend(file_evs)
            occupied.extend(file_intervals)

            # ── Сообщения ──────────────────────────────────────────────
            an_pkts3 = _ap(packets)
            if is_message_like(an_pkts3, client_ip):
                msg_evs = classify_message(
                    an_pkts3, client_ip, occupied_intervals=occupied
                )
                events.extend(msg_evs)

            if not events:
                events = [{
                    "scenario": "Unknown / Mixed traffic",
                    "direction": "Не удалось определить по содержимому",
                    "time_range": format_timestamp(packets[0].ts),
                    "src_ip": client_ip,
                    "dst_ip": "-",
                }]

            for e in events:
                if "start_ts" not in e:
                    try:
                        ts_str = e.get("time_range", "")
                        if " – " in ts_str:
                            ts_str = ts_str.split(" – ")[0]
                        e["start_ts"] = datetime.strptime(
                            ts_str, "%Y-%m-%d %H:%M:%S"
                        ).timestamp()
                    except Exception:
                        e["start_ts"] = 0.0

            events.sort(key=lambda x: x.get("start_ts", 0))

            print("=" * 130)
            print(f"{f.name}")
            for i, e in enumerate(events, 1):
                print(f"{i})")
                print(f"   Сценарий               {e.get('scenario', '')}")
                print(f"   Направление            {e.get('direction', '')}")
                print(f"   Дата и время           {e.get('time_range', '')}")
                print(f"   IP отправителя         {e.get('src_ip', '-')}")
                print(f"   IP получателя          {e.get('dst_ip', '-')}")
                print("-" * 75 + "\n")

            for e in events:
                all_events.append({"filename": f.name, **e})

        except Exception as ex:
            print(f"Ошибка при обработке {f.name}: {ex}")

    if output_path and all_events:
        with open(output_path, "w", encoding="utf-8") as outfile:
            for f_name in sorted({e["filename"] for e in all_events}):
                outfile.write("=" * 130 + "\n")
                outfile.write(f"{f_name}\n")
                file_evs = sorted(
                    [ev for ev in all_events if ev["filename"] == f_name],
                    key=lambda x: x.get("start_ts", 0),
                )
                for i, e in enumerate(file_evs, 1):
                    outfile.write(f"{i})\n")
                    outfile.write(f"   Сценарий               {e.get('scenario', '')}\n")
                    outfile.write(f"   Направление            {e.get('direction', '')}\n")
                    outfile.write(f"   Дата и время           {e.get('time_range', '')}\n")
                    outfile.write(f"   IP отправителя         {e.get('src_ip', '-')}\n")
                    outfile.write(f"   IP получателя          {e.get('dst_ip', '-')}\n")
                    outfile.write("\n")
                outfile.write("=" * 130 + "\n\n")


if __name__ == "__main__":
    main()