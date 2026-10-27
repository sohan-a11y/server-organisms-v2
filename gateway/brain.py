"""Growable brain: neurons (concepts) + instincts (confidence-scored memories).
Learns once from the LLM teacher, remembers, teaches peers. Verified heals only.
"""
import re

SEED = [
    ("sql injection dumps all users when input is interpolated into query",
     "parameterize query; bind user input as parameter, never interpolate"),
    ("broken authorization lets user read another user record by changing id",
     "check ownership on server for every record access"),
    ("reflected xss script executes in victim browser when name is rendered",
     "escape output and set content security policy"),
]


def concepts(text):
    return sorted(set(re.findall(r"[a-z_][a-z0-9_]{2,}", (text or "").lower())))


class Brain:
    def __init__(self, owner="org", llm_ask=None):
        self.owner, self.llm_ask = owner, llm_ask
        self.neurons, self.edges, self.instincts, self.pending_unknown = {}, {}, [], []
        for trig, act in SEED:
            self.learn(trig, act, source="seed", confidence=0.7)

    def _grow(self, words):
        new = 0
        for w in words:
            if w not in self.neurons:
                self.neurons[w] = 0
                new += 1
            self.neurons[w] += 1
        for a, b in zip(words, words[1:]):
            self.edges[(a, b)] = self.edges.get((a, b), 0) + 1
        return new

    def learn(self, trigger, action, source="experience", confidence=0.5):
        grew = self._grow(concepts(trigger + " " + action))
        for inst in self.instincts:
            if inst["trigger"] == trigger:
                inst["confidence"] = min(0.9, inst["confidence"] + 0.1)
                inst["evidence"] += 1
                return {"learned": "reinforced", "new_neurons": grew, "confidence": inst["confidence"]}
        self.instincts.append({"trigger": trigger, "action": action, "confidence": confidence, "evidence": 1, "source": source})
        return {"learned": "new-instinct", "new_neurons": grew, "confidence": confidence}

    def recall(self, question):
        qw = set(concepts(question))
        best, best_score = None, 0.0
        for inst in self.instincts:
            score = (len(qw & set(concepts(inst["trigger"]))) / max(1, len(qw))) * inst["confidence"]
            if score > best_score:
                best, best_score = inst, score
        shared = len(qw & set(concepts(best["trigger"]))) if best else 0
        if best and best_score > 0.08 and shared >= 2 and shared / max(1, len(qw)) >= 0.4:
            return {"known": True, "answer": best["action"], "confidence": best["confidence"], "neurons": len(self.neurons)}
        return {"known": False, "answer": None, "neurons": len(self.neurons)}

    def ask(self, question):
        hit = self.recall(question)
        if hit["known"]:
            return {**hit, "via": "memory"}
        if self.llm_ask:
            taught = self.llm_ask(question)
            if taught:
                grew = self.learn(question, taught, source="LLM-teacher", confidence=0.5)
                return {"known": True, "answer": taught, "via": "LLM taught -> learned", "grew": grew, "neurons": len(self.neurons)}
        if question.strip() and question not in self.pending_unknown:
            self.pending_unknown.append(question)
        return {"known": False, "answer": None, "via": "unknown - queued for LLM", "neurons": len(self.neurons)}

    def reward(self, trigger, success):
        for inst in self.instincts:
            if trigger in inst["trigger"]:
                inst["confidence"] = max(0.3, min(0.9, inst["confidence"] + (0.1 if success else -0.15)))
                inst["evidence"] += 1
                return inst["confidence"]
        return None

    def teach_packet(self):
        verified = [i for i in self.instincts if i["evidence"] >= 2 or i["source"] in ("seed", "experience", "heal-class")]
        return {"from": self.owner, "instincts": verified}

    def receive_teaching(self, packet):
        if packet.get("from") == self.owner:
            return {"absorbed": 0}
        absorbed = 0
        known = {i["trigger"] for i in self.instincts}
        for inst in packet.get("instincts", []):
            if inst["trigger"] not in known:
                self.learn(inst["trigger"], inst["action"], source=f"peer:{packet['from']}", confidence=max(0.3, inst["confidence"] - 0.1))
                absorbed += 1
        return {"absorbed": absorbed, "neurons": len(self.neurons)}

    def export_state(self):
        return {"neurons": self.neurons, "edges": {f"{a}|{b}": v for (a, b), v in self.edges.items()},
                "instincts": self.instincts, "pending_unknown": self.pending_unknown}

    def import_state(self, data):
        if not data:
            return
        self.neurons = data.get("neurons", self.neurons)
        self.edges = {}
        for k, v in data.get("edges", {}).items():
            a, _, b = k.partition("|")
            self.edges[(a, b)] = v
        have = {i["trigger"] for i in self.instincts}
        for inst in data.get("instincts", []):
            if inst["trigger"] not in have:
                self.instincts.append(inst)
        self.pending_unknown = data.get("pending_unknown", [])

    def snapshot(self):
        return {"owner": self.owner, "neurons": len(self.neurons), "edges": len(self.edges),
                "instincts": len(self.instincts), "pending_unknown": self.pending_unknown[-5:],
                "top_neurons": sorted(self.neurons, key=self.neurons.get, reverse=True)[:8]}
