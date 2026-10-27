"""Endocrine chemistry: drives with half-lives that modulate behaviour.
Chemicals are not labels: concentrations change parameters (heal aggressiveness,
LLM-teacher threshold, metabolism). Adapted from Creatures/HRRL design in LICHEN.
"""

HALF_LIVES = {"curiosity": 40, "fatigue": 60, "stress": 25, "reward": 30, "confidence": 90}


class Chemistry:
    def __init__(self):
        self.levels = {k: 0.3 for k in HALF_LIVES}
        self.levels["confidence"] = 0.6

    def emit(self, event):
        delta = {
            "attack": {"stress": +0.45, "curiosity": +0.15},
            "heal_success": {"reward": +0.5, "confidence": +0.2, "fatigue": +0.15},
            "heal_fail": {"stress": +0.3, "confidence": -0.2, "fatigue": +0.2},
            "idle": {"curiosity": +0.06, "fatigue": -0.03},
            "teach": {"curiosity": -0.2, "reward": +0.15},
        }.get(event, {})
        for k, v in delta.items():
            self.levels[k] = max(0.0, min(1.0, self.levels[k] + v))

    def tick(self, seconds=1.0):
        for k, hl in HALF_LIVES.items():
            decay = 0.5 ** (seconds / hl)
            self.levels[k] *= decay

    def params(self):
        return {
            "heal_aggressiveness": round(0.4 + 0.6 * self.levels["stress"], 2),
            "ask_teacher_threshold": round(1.0 - 0.5 * self.levels["curiosity"], 2),
            "metabolism_food_multiplier": round(1.0 + self.levels["reward"], 2),
        }

    def snapshot(self):
        return {"levels": {k: round(v, 2) for k, v in self.levels.items()}, "params": self.params()}
