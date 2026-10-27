"""Artificial life: metabolism, heredity, reproduction, death, selection."""
import random
import time
import uuid


class Genome:
    def __init__(self, heal_rate=0.32, harm_rate=0.09, signal_decay=0.65, mutation=0.05):
        self.heal_rate, self.harm_rate, self.signal_decay, self.mutation = heal_rate, harm_rate, signal_decay, mutation

    def mutate(self, rng):
        m = self.mutation
        clamp = lambda v, lo, hi: max(lo, min(hi, v))  # noqa: E731
        return Genome(clamp(self.heal_rate + rng.uniform(-m, m), 0.02, 0.5),
                      clamp(self.harm_rate + rng.uniform(-m, m), 0.02, 0.5),
                      clamp(self.signal_decay + rng.uniform(-m, m), 0.4, 0.98), m)

    def to_dict(self):
        return {"heal_rate": round(self.heal_rate, 3), "harm_rate": round(self.harm_rate, 3), "signal_decay": round(self.signal_decay, 3)}


class Organism:
    MAX_AGE, REPRO_COST, REPRO_THRESHOLD = 900, 6.0, 14.0

    def __init__(self, genome=None, generation=0, parent=None, rng=None):
        self.id = uuid.uuid4().hex[:8]
        self.genome = genome or Genome()
        self.generation, self.parent = generation, parent
        self.energy, self.age, self.heals, self.failures = 10.0, 0, 0, 0
        self.born = time.strftime("%H:%M:%S")
        self.rng = rng or random.Random()

    @property
    def fitness(self):
        t = self.heals + self.failures
        return self.heals / t if t else 0.5

    def tick(self, food=0.0):
        self.age += 1
        self.energy += food - 1.0
        if self.energy <= 0:
            return "starved"
        if self.age > self.MAX_AGE:
            return "old age"
        return None

    def reproduce(self):
        if self.energy < self.REPRO_THRESHOLD:
            return None
        self.energy -= self.REPRO_COST
        child = Organism(self.genome.mutate(self.rng), self.generation + 1, self.id, self.rng)
        child.energy = self.REPRO_COST
        return child

    def record(self, healed):
        if healed:
            self.heals += 1
            self.energy += 4.0
        else:
            self.failures += 1
            self.energy -= 2.0

    def to_dict(self):
        return {"id": self.id, "gen": self.generation, "parent": self.parent, "energy": round(self.energy, 1),
                "age": self.age, "fitness": round(self.fitness, 2), "heals": self.heals,
                "genome": self.genome.to_dict(), "born": self.born}


class Population:
    MAX_POP = 24

    def __init__(self, seed=7, founder_genome=None):
        self.rng = random.Random(seed)
        self.members = [Organism(founder_genome, rng=self.rng) for _ in range(6)]
        self.graveyard, self.births = [], 0

    def tick(self, food_per=0.45):
        for o in list(self.members):
            cause = o.tick(food=self.rng.uniform(0, food_per * 2))
            if cause:
                self.members.remove(o)
                self.graveyard.append({"id": o.id, "gen": o.generation, "cause": cause, "fitness": round(o.fitness, 2)})
        for o in list(self.members):
            child = o.reproduce()
            if child:
                self.members.append(child)
                self.births += 1
        if len(self.members) > self.MAX_POP:
            self.members.sort(key=lambda x: x.fitness, reverse=True)
            for c in self.members[self.MAX_POP:]:
                self.graveyard.append({"id": c.id, "gen": c.generation, "cause": "selected out", "fitness": round(c.fitness, 2)})
            self.members = self.members[:self.MAX_POP]

    def record_outcome(self, healed):
        if self.members:
            max(self.members, key=lambda x: x.fitness).record(healed)

    def leader_genome(self):
        if not self.members:
            return Genome()
        return max(self.members, key=lambda x: x.fitness).genome

    def export_state(self):
        return {"members": [{"genome": o.genome.to_dict(), "generation": o.generation, "parent": o.parent,
                             "energy": o.energy, "age": o.age, "heals": o.heals, "failures": o.failures, "id": o.id}
                            for o in self.members], "graveyard": self.graveyard, "births": self.births}

    def import_state(self, data):
        if not data or not data.get("members"):
            return
        self.members = []
        for m in data["members"]:
            g = m["genome"]
            o = Organism(Genome(g["heal_rate"], g["harm_rate"], g["signal_decay"]), m["generation"], m.get("parent"), self.rng)
            o.id, o.energy, o.age, o.heals, o.failures = m["id"], m["energy"], m["age"], m["heals"], m["failures"]
            self.members.append(o)
        self.graveyard, self.births = data.get("graveyard", []), data.get("births", 0)

    def snapshot(self):
        return {"population": len(self.members), "births": self.births, "deaths": len(self.graveyard),
                "max_generation": max((o.generation for o in self.members), default=0),
                "organisms": [o.to_dict() for o in self.members], "graveyard": self.graveyard[-8:]}
