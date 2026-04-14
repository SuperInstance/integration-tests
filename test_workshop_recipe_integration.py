"""
test_workshop_recipe_integration.py — Workshop × Recipes (~150 lines)

Cross-agent integration tests verifying recipes can be created in tiers,
promoted between them, workshop narratives capture full history, and
interpreter compilation works for recipes.
"""

import sys
import os
import json
import tempfile
import shutil
import unittest
from pathlib import Path

FLEET_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FLEET_ROOT / "git-agent"))

from workshop_template import (
    WorkshopTemplate, LanguageStack, RecipeMeta, WorkshopConfig,
)
from bootcamp import Bootcamp, Dojo, Rank, ExerciseType
from narrator import (
    CommitNarrator, CommitType, NarrativeStyle, Commit,
    Narrative,
)


class TestRecipeCreation(unittest.TestCase):
    """Recipes can be created in hot/med/cold tiers."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.tmpl = WorkshopTemplate()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_add_cold_recipe(self):
        """Cold recipe is created in the cold tier directory."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        meta = self.tmpl.add_recipe(
            workshop_path=str(ws),
            name="ref_sort",
            content="# Reference bubble sort implementation\n"
                   "def bubble_sort(arr):\n    n = len(arr)\n    for i in range(n):\n        for j in range(n-i-1):\n"
                   "            if arr[j] > arr[j+1]:\n                arr[j], arr[j+1] = arr[j+1], arr[j]\n"
                   "    return arr\n",
            tier="cold",
            language="python",
            description="Reference implementation",
        )
        self.assertEqual(meta.tier, "cold")
        self.assertTrue((ws / "recipes" / "cold" / "ref_sort.py").exists())

    def test_add_med_recipe(self):
        """Med recipe is created in the med tier directory."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        meta = self.tmpl.add_recipe(
            workshop_path=str(ws),
            name="fast_sort",
            content="def quicksort(arr):\n    pass\n",
            tier="med",
            language="python",
        )
        self.assertEqual(meta.tier, "med")
        self.assertTrue((ws / "recipes" / "med" / "fast_sort.py").exists())

    def test_add_hot_recipe(self):
        """Hot recipe is created in the hot tier directory."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        meta = self.tmpl.add_recipe(
            workshop_path=str(ws),
            name="opt_sort",
            content="# Optimized sort\n",
            tier="hot",
            language="python",
        )
        self.assertEqual(meta.tier, "hot")
        self.assertTrue((ws / "recipes" / "hot" / "opt_sort.py").exists())

    def test_invalid_tier_raises(self):
        """Invalid tier name raises ValueError."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        with self.assertRaises(ValueError):
            self.tmpl.add_recipe(
                workshop_path=str(ws),
                name="bad",
                content="x",
                tier="invalid",
            )


class TestRecipePromotion(unittest.TestCase):
    """Recipes can be promoted between tiers."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.tmpl = WorkshopTemplate()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_promote_cold_to_med(self):
        """Recipe moves from cold to med tier."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        self.tmpl.add_recipe(str(ws), "sort_v1", "code", tier="cold")
        promoted = self.tmpl.promote_recipe(str(ws), "sort_v1", "cold", "med")
        self.assertTrue(promoted.exists())
        self.assertTrue((ws / "recipes" / "med" / "sort_v1.py").exists())
        self.assertFalse((ws / "recipes" / "cold" / "sort_v1.py").exists())

    def test_promote_med_to_hot(self):
        """Recipe moves from med to hot tier."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        self.tmpl.add_recipe(str(ws), "sort_v2", "code", tier="med")
        promoted = self.tmpl.promote_recipe(str(ws), "sort_v2", "med", "hot")
        self.assertTrue(promoted.exists())
        self.assertTrue((ws / "recipes" / "hot" / "sort_v2.py").exists())
        self.assertFalse((ws / "recipes" / "med" / "sort_v2.py").exists())

    def test_promote_cold_to_hot(self):
        """Recipe can be promoted directly from cold to hot."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        self.tmpl.add_recipe(str(ws), "fast_search", "code", tier="cold")
        promoted = self.tmpl.promote_recipe(str(ws), "fast_search", "cold", "hot")
        self.assertTrue(promoted.exists())
        self.assertTrue((ws / "recipes" / "hot" / "fast_search.py").exists())
        self.assertFalse((ws / "recipes" / "cold" / "fast_search.py").exists())
        self.assertFalse((ws / "recipes" / "med" / "fast_search.py").exists())

    def test_demotion_raises(self):
        """Cannot demote (hot to cold raises ValueError)."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        self.tmpl.add_recipe(str(ws), "sort_v3", "code", tier="med")
        with self.assertRaises(ValueError):
            self.tmpl.promote_recipe(str(ws), "sort_v3", "med", "cold")

    def test_promote_nonexistent_raises(self):
        """Promoting a non-existent recipe raises FileNotFoundError."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        with self.assertRaises(FileNotFoundError):
            self.tmpl.promote_recipe(str(ws), "ghost", "cold", "med")

    def test_freeze_recipe(self):
        """Recipe can be frozen after creation."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        self.tmpl.add_recipe(str(ws), "stable_fn", "def stable(): pass", tier="hot")
        self.tmpl.freeze_recipe(str(ws), "stable_fn", "hot")
        self.assertTrue((ws / "recipes" / "hot" / "stable_fn.frozen").exists())


class TestWorkshopNarrative(unittest.TestCase):
    """Workshop narrative captures the full history."""

    def test_multi_day_narrative(self):
        """Narrative covers commits across multiple days."""
        narrator = CommitNarrator()
        commits = []
        for day, subjects in [
            ("2025-01-15", ["feat: add database layer", "test: add db tests"]),
            ("2025-01-16", ["fix: connection leak", "refactor: extract pool"]),
            ("2025-01-17", ["feat: add caching", "docs: update README"]),
        ]:
            for subj in subjects:
                commits.append(Commit(
                    hash=f"hash-{day.replace('-', '')}-{subj[:10]}",
                    short_hash=f"h{subj[:6]}",
                    author="Agent",
                    date=None,  # will use datetime.now()
                    message=subj,
                    subject=subj,
                    body="",
                ))
                commits[-1].date = __import__("datetime").datetime.strptime(
                    f"{day} 12:00:00", "%Y-%m-%d %H:%M:%S"
                )
                commits[-1].commit_type = narrator.classify_commit(subj)

        narrative = narrator.generate_narrative(commits, NarrativeStyle.STORY)
        self.assertIn("2025", narrative.text)
        self.assertGreater(narrative.commits_covered, 0)

    def test_experiment_narrative(self):
        """Narrative captures experimental patterns."""
        narrator = CommitNarrator()
        commits = [
            Commit(hash="h1", short_hash="h1", author="A", date=None,
                   message="try: vectorized computation",
                   subject="try: vectorized computation", body=""),
            Commit(hash="h2", short_hash="h2", author="A", date=None,
                   message="fix: segfault in vec impl",
                   subject="fix: segfault in vec impl", body=""),
            Commit(hash="h3", short_hash="h3", author="A", date=None,
                   message="try: vectorized computation again",
                   subject="try: vectorized computation again", body=""),
            Commit(hash="h4", short_hash="h4", author="A", date=None,
                   message="fix: resolved alignment issue",
                   subject="fix: resolved alignment issue", body=""),
        ]
        # Set dates
        import datetime
        for i, c in enumerate(commits):
            c.date = datetime.datetime(2025, 1, 15 + i, 10, 0, 0)
        commits[0].commit_type = narrator.classify_commit(commits[0].subject)

        narrative = narrator.generate_narrative(commits, NarrativeStyle.STORY)
        self.assertGreater(narrative.experiments_detected, 0)

    def test_brief_timeline(self):
        """Timeline is generated for commits."""
        narrator = CommitNarrator()
        commits = [
            Commit(hash="h1", short_hash="h1", author="A",
                   date=datetime.datetime(2025, 1, 15, 10, 0, 0),
                   message="feat: first", subject="feat: first", body=""),
            Commit(hash="h2", short_hash="h2", author="A",
                   date=datetime.datetime(2025, 1, 16, 10, 0, 0),
                   message="feat: second", subject="feat: second", body=""),
        ]
        commits[0].commit_type = CommitType.FEATURE
        commits[1].commit_type = CommitType.FEATURE

        narrative = narrator.generate_narrative(commits, NarrativeStyle.BRIEF)
        self.assertIn("timeline", narrative.timeline)
        self.assertIn("2025-01-15", narrative.timeline)
        self.assertIn("2025-01-16", narrative.timeline)


class TestInterpreterCompilation(unittest.TestCase):
    """Interpreter compilation works for recipes."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.tmpl = WorkshopTemplate()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_python_recipe_has_valid_syntax(self):
        """Python recipes have valid syntax (compilable)."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        code = (
            "def fibonacci(n: int) -> list[int]:\n"
            "    if n <= 1:\n        return [n]\n"
            "    result = [0, 1]\n"
            "    for i in range(2, n):\n"
            "        result.append(result[-1] + result[-2])\n"
            "    return result\n"
        )
        self.tmpl.add_recipe(str(ws), "fibonacci", code, tier="hot", language="python")
        recipe_path = ws / "recipes" / "hot" / "fibonacci.py"
        content = recipe_path.read_text()
        compile(content, recipe_path, "exec")
        self.assertEqual(content, code)

    def test_bash_recipe_creation(self):
        """Bash recipes can be created."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        code = '#!/bin/bash\necho "Hello from bash recipe"\n'
        meta = self.tmpl.add_recipe(str(ws), "hello", code, tier="med", language="bash")
        self.assertEqual(meta.language, "bash")
        self.assertTrue((ws / "recipes" / "med" / "hello.sh").exists())

    def test_rust_recipe_creation(self):
        """Rust recipes can be created."""
        ws = self.tmp / "ws"
        self.tmpl.create_workshop(path=str(ws), agent_role="recipe-agent")
        code = 'fn main() { println!("Hello Rust!"); }\n'
        meta = self.tmpl.add_recipe(str(ws), "hello_rust", code, tier="cold", language="rust")
        self.assertEqual(meta.language, "rust")
        self.assertTrue((ws / "recipes" / "cold" / "hello_rust.rs").exists())


if __name__ == "__main__":
    unittest.main()
