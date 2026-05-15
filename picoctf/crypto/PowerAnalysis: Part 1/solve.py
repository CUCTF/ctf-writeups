#!/usr/bin/env python3
import argparse
import socket
import ast
import os
import time
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

HOST = "saturn.picoctf.net"

SBOX = np.array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
], dtype=np.uint8)

HW = np.array([bin(i).count('1') for i in range(256)], dtype=np.uint8)


def recv_until(sock, marker):
    buf = b""
    while marker not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("Server closed connection unexpectedly")
        buf += chunk
    return buf


def collect_one_trace(port, max_retries=8):
    for attempt in range(max_retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((HOST, port))
                sock.settimeout(15)
                recv_until(sock, b"hex:")
                pt = os.urandom(16)
                sock.sendall(pt.hex().encode() + b"\n")
                response = recv_until(sock, b"]")
            start = response.index(b"[")
            end   = response.index(b"]") + 1
            return pt, ast.literal_eval(response[start:end].decode())
        except Exception:
            if attempt == max_retries - 1:
                raise
            time.sleep(0.5 * (attempt + 1))


def cpa_attack(plaintexts, traces, verbose=False):
    n      = len(plaintexts)
    pt_arr = np.frombuffer(b"".join(plaintexts), dtype=np.uint8).reshape(n, 16)

    traces_c   = traces - traces.mean(axis=0)
    traces_std = traces_c.std(axis=0)

    key       = []
    byte_iter = range(16)
    for byte_pos in byte_iter:
        xor   = pt_arr[:, byte_pos, None] ^ np.arange(256, dtype=np.uint8)  # (n, 256)
        hyp   = HW[SBOX[xor]].astype(float)
        hyp_c = hyp - hyp.mean(axis=0)
        corr  = (hyp_c.T @ traces_c) / (n * np.outer(hyp_c.std(axis=0), traces_std) + 1e-12)
        peak  = np.abs(corr).max(axis=1)
        best_k = int(peak.argmax())
        key.append(best_k)
        if verbose:
            tqdm.write(f"   byte {byte_pos:2d}: 0x{best_k:02x}  (peak |r| = {peak[best_k]:.4f})")

    return bytes(key)


def collect_all_traces(port, n=300, workers=3, initial=None):
    all_pts, all_traces = [], []
    if initial is not None:
        all_pts.append(initial[0])
        all_traces.append(initial[1])

    remaining = n - len(all_pts)

    with tqdm(total=n, initial=len(all_pts), desc="Collecting traces", unit="trace", position=0) as pbar, \
         tqdm(bar_format="  Est. AES key: {desc}", desc="[collecting first trace...]",
              position=1, leave=True) as flag_bar:

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(collect_one_trace, port) for _ in range(remaining)]
            for f in as_completed(futures):
                try:
                    pt, trace = f.result()
                except Exception as e:
                    tqdm.write(f"  [warn] trace failed: {e}")
                    continue
                all_pts.append(pt)
                all_traces.append(trace)
                pbar.update(1)
                est = cpa_attack(all_pts, np.array(all_traces, dtype=float))
                flag_bar.set_description_str(f"{est.hex()}")

    print()
    return all_pts, np.array(all_traces, dtype=float)


def compute_correlations(plaintexts, traces):
    """Return correlation tensor of shape (16, 256, n_samples)."""
    n      = len(plaintexts)
    pt_arr = np.frombuffer(b"".join(plaintexts), dtype=np.uint8).reshape(n, 16)
    traces_c   = traces - traces.mean(axis=0)
    traces_std = traces_c.std(axis=0)
    corr = np.zeros((16, 256, traces.shape[1]))
    for byte_pos in range(16):
        xor   = pt_arr[:, byte_pos, None] ^ np.arange(256, dtype=np.uint8)
        hyp   = HW[SBOX[xor]].astype(float)
        hyp_c = hyp - hyp.mean(axis=0)
        corr[byte_pos] = (hyp_c.T @ traces_c) / (
            n * np.outer(hyp_c.std(axis=0), traces_std) + 1e-12
        )
    return corr


def save_plots(plaintexts, traces, key, out_dir="plots"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    os.makedirs(out_dir, exist_ok=True)
    n_samples = traces.shape[1]
    corr_abs = np.abs(compute_correlations(plaintexts, traces))  # (16, 256, n_samples)

    # 1. Correlation over time — winning key (red) vs range of all others (grey band)
    fig, axes = plt.subplots(4, 4, figsize=(20, 12), sharex=True)
    for byte_pos, ax in enumerate(axes.flat):
        best_k  = key[byte_pos]
        others  = np.delete(corr_abs[byte_pos], best_k, axis=0)
        ax.fill_between(range(n_samples), others.min(axis=0), others.max(axis=0),
                        color="lightgrey", label="other candidates")
        ax.plot(corr_abs[byte_pos, best_k], color="red", linewidth=0.8,
                label=f"0x{best_k:02x}")
        ax.set_title(f"Byte {byte_pos}", fontsize=8)
        ax.legend(fontsize=6, loc="upper right")
        ax.set_xlabel("Sample index", fontsize=6)
        ax.set_ylabel("Pearson |r|", fontsize=6)
        ax.set_xticks(range(0, n_samples, 500))
        ax.tick_params(labelsize=5, labelbottom=True)
    fig.suptitle("Correlation over time  (red = recovered key byte, grey band = range of all other candidates)")
    fig.tight_layout()
    path = os.path.join(out_dir, "correlation_time.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {path}")

    # 2. Peak correlation per candidate — bar chart per byte
    fig, axes = plt.subplots(4, 4, figsize=(20, 12))
    for byte_pos, ax in enumerate(axes.flat):
        best_k = key[byte_pos]
        peaks  = corr_abs[byte_pos].max(axis=1)
        ax.bar(range(256), peaks, color="steelblue", width=1.0)
        ax.annotate(f"{peaks[best_k]:.3f}", xy=(best_k, peaks[best_k]),
                    xytext=(0, 4), textcoords="offset points",
                    ha="center", va="bottom", fontsize=6, clip_on=False)
        ax.set_title(f"Byte {byte_pos}", fontsize=8)
        ax.set_xlabel("Key candidate (0–255)", fontsize=6)
        ax.set_ylabel("Peak Pearson |r|", fontsize=6)
        ax.set_xlim(0, 255)
        ax.set_ylim(0, 0.7)
        ax.tick_params(labelsize=5)
    fig.suptitle("Peak correlation per key candidate  (annotated bar = recovered byte)")
    fig.tight_layout()
    path = os.path.join(out_dir, "peak_correlation.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {path}")



def save_gif(plaintexts, traces, key, out_dir="plots", step=5):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.animation import FuncAnimation, PillowWriter

    os.makedirs(out_dir, exist_ok=True)
    n = len(plaintexts)
    frame_sizes = list(range(step, n + 1, step))
    if frame_sizes[-1] != n:
        frame_sizes.append(n)

    frames_peaks = []
    for k in tqdm(frame_sizes, desc="  Precomputing frames"):
        corr_abs = np.abs(compute_correlations(plaintexts[:k], traces[:k]))
        frames_peaks.append(corr_abs.max(axis=2))

    fig, axes = plt.subplots(4, 4, figsize=(20, 12))
    title = fig.suptitle("")
    bars_list, ann_list = [], []
    for byte_pos, ax in enumerate(axes.flat):
        bars = ax.bar(range(256), np.zeros(256), color="steelblue", width=1.0)
        ann  = ax.annotate("", xy=(key[byte_pos], 0), xytext=(0, 4),
                           textcoords="offset points", ha="center", va="bottom",
                           fontsize=6, clip_on=False)
        ax.set_title(f"Byte {byte_pos}", fontsize=8)
        ax.set_xlabel("Key candidate (0–255)", fontsize=6)
        ax.set_ylabel("Peak Pearson |r|", fontsize=6)
        ax.set_xlim(0, 255)
        ax.set_ylim(0, 0.7)
        ax.tick_params(labelsize=5)
        bars_list.append(bars)
        ann_list.append(ann)

    def update(frame_idx):
        peaks_all = frames_peaks[frame_idx]
        for byte_pos in range(16):
            peaks = peaks_all[byte_pos]
            for bar, h in zip(bars_list[byte_pos], peaks):
                bar.set_height(h)
            best_k = key[byte_pos]
            ann_list[byte_pos].xy = (best_k, peaks[best_k])
            ann_list[byte_pos].set_text(f"{peaks[best_k]:.3f}")
        title.set_text(f"Peak correlation per key candidate — {frame_sizes[frame_idx]} traces")

    fig.tight_layout()
    anim = FuncAnimation(fig, update, frames=len(frame_sizes), interval=150)
    path = os.path.join(out_dir, "peak_correlation.gif")
    with tqdm(total=len(frame_sizes), desc="  Rendering GIF") as pbar:
        anim.save(path, writer=PillowWriter(fps=8),
                  progress_callback=lambda i, n: pbar.update(1))
    plt.close(fig)
    print(f"  Saved: {path}")


def main():
    parser = argparse.ArgumentParser(description="CPA attack on AES power traces")
    parser.add_argument("port",           type=int, nargs="?",           help="Server port (not required with --load-traces)")
    parser.add_argument("--traces",       type=int, default=300, metavar="N", help="Number of traces to collect (default: 300)")
    parser.add_argument("--workers",      type=int, default=3,   metavar="N", help="Parallel connections (default: 3)")
    parser.add_argument("--plots",        action="store_true",                help="Save diagnostic plots to plots/")
    parser.add_argument("--gif",          action="store_true",                help="Save animated GIF of CPA to plots/")
    parser.add_argument("--save-traces",  metavar="PATH",                     help="Save collected traces to a .npz file")
    parser.add_argument("--load-traces",  metavar="PATH",                     help="Load traces from a .npz file instead of collecting")
    args = parser.parse_args()

    if args.load_traces:
        print(f"Loading traces from {args.load_traces}...")
        data       = np.load(args.load_traces)
        traces     = data["traces"]
        plaintexts = [bytes(row) for row in data["plaintexts"]]
        print(f"  Loaded {len(plaintexts)} traces × {traces.shape[1]} samples")
    else:
        if args.port is None:
            parser.error("port is required unless --load-traces is specified")
        try:
            initial = collect_one_trace(port=args.port)
        except Exception as e:
            print(f"Server connection failed: {e}")
            raise
        print(f"Collecting {args.traces} traces using {args.workers} parallel connections...")
        plaintexts, traces = collect_all_traces(
            port=args.port, n=args.traces, workers=args.workers, initial=initial,
        )

    if args.save_traces:
        pt_arr = np.frombuffer(b"".join(plaintexts), dtype=np.uint8).reshape(len(plaintexts), 16)
        np.savez(args.save_traces, traces=traces, plaintexts=pt_arr)
        print(f"Traces saved to {args.save_traces}.npz")

    print(f"Running CPA on {len(plaintexts)} traces × {traces.shape[1]} samples")
    key = cpa_attack(plaintexts, traces, verbose=True)
    print(f"Flag: picoCTF{{{key.hex()}}}")

    if args.plots:
        print("Saving plots...")
        save_plots(plaintexts, traces, key)

    if args.gif:
        print("Saving GIF...")
        save_gif(plaintexts, traces, key)


if __name__ == "__main__":
    main()
