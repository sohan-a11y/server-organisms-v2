"""Leaky Neural Cellular Automata tissue.

A1 finding adopted from NCA-Pet-0: persistent state needs a restoring force.
Update: state <- clamp(state + fire*(update - LEAK*state)), LEAK=0.3.
Saturation regression lives in tests/test_saturation.py.
"""
LEAK = 0.3
W = H = 16


class NCAGrid:
    def __init__(self, genome=None):
        g = genome or {}
        self.heal_rate = g.get("heal_rate", 0.32)
        self.harm_rate = g.get("harm_rate", 0.09)
        self.signal_decay = g.get("signal_decay", 0.65)
        self.reset()

    def reset(self):
        self.health = [[1.0] * W for _ in range(H)]
        self.damage = [[0.0] * W for _ in range(H)]
        self.signal = [[0.0] * W for _ in range(H)]

    def wound(self, strength=1.0):
        cx = cy = W // 2
        for y in range(H):
            for x in range(W):
                d = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
                if d < 4:
                    self.damage[y][x] = min(1.0, strength * (1 - d / 5))
                    self.signal[y][x] = 1.0

    def step(self):
        nh = [r[:] for r in self.health]
        nd = [r[:] for r in self.damage]
        ns = [r[:] for r in self.signal]
        for y in range(H):
            for x in range(W):
                vals = []
                for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                    nx, ny = x + dx, y + dy
                    if 0 <= nx < W and 0 <= ny < H:
                        vals.append((self.health[ny][nx], self.damage[ny][nx], self.signal[ny][nx]))
                n = max(len(vals), 1)
                mh = sum(v[0] for v in vals) / n
                md = sum(v[1] for v in vals) / n
                ms = sum(v[2] for v in vals) / n
                harm = self.harm_rate * self.damage[y][x] + 0.08 * md
                heal = self.heal_rate * mh if self.damage[y][x] < 0.9 else 0.02
                raw_h = self.health[y][x] - harm + heal
                nh[y][x] = max(-4.0, min(4.0, raw_h - LEAK * 0.05 * raw_h))
                nh[y][x] = max(0.0, min(1.0, nh[y][x]))
                nd[y][x] = max(0.0, min(1.0, self.damage[y][x] - 0.10 * mh + 0.03 * md - LEAK * 0.02 * self.damage[y][x]))
                ns[y][x] = max(0.0, min(1.0, self.signal[y][x] * self.signal_decay + 0.3 * ms + 0.4 * self.damage[y][x]))
        self.health, self.damage, self.signal = nh, nd, ns

    def heal_all(self):
        for y in range(H):
            for x in range(W):
                self.damage[y][x] *= 0.15

    def saturation(self):
        flat = [v for row in self.health for v in row]
        return sum(1 for v in flat if v >= 0.999 or v <= 0.001) / len(flat)

    def snapshot(self):
        cells, alive = [], 0
        for y in range(H):
            row = []
            for x in range(W):
                h = round(self.health[y][x], 2)
                alive += h > 0.3
                row.append({"h": h, "d": round(self.damage[y][x], 2), "s": round(self.signal[y][x], 2)})
            cells.append(row)
        return {"w": W, "h": H, "alive_cells": alive, "total": W * H, "cells": cells, "saturation": round(self.saturation(), 3)}
