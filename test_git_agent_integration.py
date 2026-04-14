"""
test_git_agent_integration.py — Git Agent × Workshop (~200 lines)

Cross-agent integration tests verifying the Git Agent's workshop creation,
commit narration, bootcamp enrollment, and dojo technique library
all work together correctly.
"""

import sys
import os
import json
import tempfile
import shutil
import unittest
from pathlib import Path

# Add git-agent to path
FLEET_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FLEET_ROOT / "git-agent"))

from git_agent import GitAgent
from narrator import (
    Commit, CommitNarrator, CommitType, NarrativeStyle,
)
from bootcamp import Bootcamp, Dojo, Rank, ExerciseType
from workshop_template import (
    WorkshopTemplate, LanguageStack, WorkshopConfig, RecipeMeta,
)


class TestWorkshopCreation(unittest.TestCase):
    """Git agent can create a workshop from the template."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_create_workshop_structure(self):
        """Workshop template creates all required directories."""
        tmpl = WorkshopTemplate()
        config = tmpl.create_workshop(
            path=str(self.tmp / "test-workshop"),
            agent_role="Test Agent",
            language_stack=LanguageStack.AUTOMATION,
        )
        self.assertEqual(config.agent_name, "test-workshop")
        self.assertEqual(config.language_stack, LanguageStack.AUTOMATION)

        ws = Path(config.path)
        self.assertTrue((ws / "recipes" / "hot").is_dir())
        self.assertTrue((ws / "recipes" / "med").is_dir())
        self.assertTrue((ws / "recipes" / "cold").is_dir())
        self.assertTrue((ws / "bootcamp" / "exercises").is_dir())
        self.assertTrue((ws / "dojo" / "techniques").is_dir())
        self.assertTrue((ws / ".superinstance" / "agent.yaml").is_file())
        self.assertTrue((ws / "README.md").is_file())
        self.assertTrue((ws / "CHARTER.md").is_file())

    def test_create_workshop_full_stack(self):
        """Full stack creates source directories for all languages."""
        tmpl = WorkshopTemplate()
        config = tmpl.create_workshop(
            path=str(self.tmp / "full-ws"),
            agent_role="Full Stack Agent",
            language_stack=LanguageStack.FULL,
        )
        ws = Path(config.path)
        self.assertTrue((ws / "src" / "python").is_dir())
        self.assertTrue((ws / "src" / "rust").is_dir())
        self.assertTrue((ws / "src" / "c").is_dir())
        self.assertTrue((ws / "src" / "typescript").is_dir())

    def test_git_agent_spawns_workshop(self):
        """spawn_git_agent creates workshop and registers it."""
        ga = GitAgent(fleet_root=str(self.tmp / "fleet"))
        ws_path = str(self.tmp / "fleet" / "workshops" / "test-agent")
        ga.bootcamp  # triggers _data_dir creation
        config = ga.spawn_git_agent("test-agent", ws_path)
        self.assertEqual(config.language_stack, LanguageStack.FULL)
        reg = ga._workshops.get("test-agent")
        self.assertIsNotNone(reg)
        self.assertEqual(reg.status, "active")


class TestCommitNarration(unittest.TestCase):
    """Narrator can parse commit history and generate narratives."""

    def test_parse_conventional_commit(self):
        """Conventional commits are classified correctly."""
        narrator = CommitNarrator()
        self.assertEqual(
            narrator.classify_commit("feat: add user authentication"),
            CommitType.FEATURE,
        )
        self.assertEqual(
            narrator.classify_commit("fix: resolve login bug"),
            CommitType.FIX,
        )
        self.assertEqual(
            narrator.classify_commit("refactor: extract parser module"),
            CommitType.REFACTOR,
        )
        self.assertEqual(
            narrator.classify_commit("test: add auth unit tests"),
            CommitType.TEST,
        )

    def test_parse_experiment_keywords(self):
        """Experiment commits are detected by keywords."""
        narrator = CommitNarrator()
        self.assertEqual(
            narrator.classify_commit("Trying a new approach for caching"),
            CommitType.EXPERIMENT,
        )
        self.assertEqual(
            narrator.classify_commit("attempt: prototype for notifications"),
            CommitType.EXPERIMENT,
        )

    def test_parse_git_log_format(self):
        """Git log output is parsed into Commit objects."""
        narrator = CommitNarrator()
        log = """COMMIT_START
Hash: abcdef1234567890
Short: abcdef1
Author: Test Agent
Date: 2025-01-15T10:30:00Z
Subject: feat: implement search
COMMIT_END
COMMIT_START
Hash: fedcba0987654321
Short: fedcba0
Author: Test Agent
Date: 2025-01-16T14:00:00Z
Subject: fix: handle null pointer
COMMIT_END"""
        commits = narrator.parse_log(log)
        self.assertEqual(len(commits), 2)
        self.assertEqual(commits[0].commit_type, CommitType.FEATURE)
        self.assertEqual(commits[1].commit_type, CommitType.FIX)

    def test_narrative_generation(self):
        """Narrator generates text for various styles."""
        narrator = CommitNarrator()
        log = """COMMIT_START
Hash: abcdef1234567890
Short: abcdef1
Author: Test Agent
Date: 2025-01-15T10:30:00Z
Subject: feat: implement search
COMMIT_END"""
        commits = narrator.parse_log(log)

        for style in NarrativeStyle:
            narrative = narrator.generate_narrative(commits, style)
            self.assertIn(narrative.text, ["feat", "implement", "search", "abcdef1"])
            self.assertEqual(narrative.commits_covered, 1)

    def test_stuck_pattern_detection(self):
        """Repeated similar commits are flagged as stuck patterns."""
        narrator = CommitNarrator()
        log = "\n".join(
            f"COMMIT_START\nShort: abc{i}\nAuthor: A\nDate: 2025-01-15T10:30:00Z\nSubject: fix bug X\nCOMMIT_END"
            for i in range(6)
        )
        commits = narrator.parse_log(log)
        stuck = narrator.detect_stuck_patterns(commits)
        self.assertTrue(len(stuck) > 0)


class TestBootcampEnrollment(unittest.TestCase):
    """Bootcamp enrollment works end-to-end."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_enroll_agent(self):
        """Agent can enroll in bootcamp."""
        bc = Bootcamp(progress_dir=str(self.tmp / "bootcamp"))
        progress = bc.enroll("coder-agent")
        self.assertTrue(progress.enrolled)
        self.assertEqual(progress.rank, Rank.NOVICE)
        self.assertEqual(len(progress.exercises_completed), 0)

    def test_complete_exercise_awards_xp(self):
        """Completing an exercise awards XP."""
        bc = Bootcamp(progress_dir=str(self.tmp / "bootcamp"))
        bc.enroll("coder-agent")
        result = bc.complete_exercise("coder-agent", "hello_workshop", time_taken_seconds=30)
        self.assertTrue(result.completed)
        self.assertGreater(result.xp_earned, 0)

    def test_xp_accumulates_and_advances_rank(self):
        """Accumulated XP triggers rank advancement."""
        bc = Bootcamp(progress_dir=str(self.tmp / "bootcamp"))
        bc.enroll("coder-agent")
        # hello_workshop = 20 XP, parse_config = 20 XP, recipe_runner = 30 XP, log_analyzer = 25 XP = 95 XP
        bc.complete_exercise("coder-agent", "hello_workshop")
        bc.complete_exercise("coder-agent", "parse_config")
        bc.complete_exercise("coder-agent", "recipe_runner", time_taken_seconds=60)
        bc.complete_exercise("coder-agent", "log_analyzer", time_taken_seconds=45)
        bc.complete_exercise("coder-agent", "hello_workshop")

        progress = bc.get_progress("coder-agent")
        self.assertGreaterEqual(progress.xp, 100)
        self.assertGreaterEqual(progress.rank, Rank.APPRENTICE)

    def test_available_exercises_filtered_by_rank(self):
        """Available exercises are filtered by agent rank."""
        bc = Bootcamp(progress_dir=str(self.tmp / "bootcamp))
        bc.enroll("coder-agent")
        available = bc.get_available_exercises("coder-agent")
        # Novice has access to exercises with required_rank <= 1
        for ex in available:
            self.assertLessEqual(ex.required_rank, Rank.NOVICE)

    def test_fail_exercise_records_failure(self):
        """Failed exercises are tracked."""
        bc = Bootcamp(progress_dir=str(self.tmp / "bootcamp"))
        bc.enroll("coder-agent")
        bc.fail_exercise("coder-agent", "hello_workshop")
        progress = bc.get_progress("coder-agent")
        self.assertIn("hello_workshop", progress.exercises_failed)


class TestDojoTechniqueLibrary(unittest.TestCase):
    """Dojo technique library works."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors)

    def test_learn_technique(self):
        """Technique can be learned and stored."""
        dojo = Dojo(progress_dir=str(self.tmp / "dojo"))
        tech = dojo.learn_technique(
            name="error_boundary",
            code="try: ... except: ...",
            description="Boundary error handling pattern",
            category="error-handling",
        )
        self.assertEqual(tech.name, "error_boundary")
        self.assertEqual(tech.category, "error-handling")
        self.assertEqual(tech.mastery_level, 0.0)
        self.assertEqual(tech.times_practiced, 0)

    def test_practice_increases_mastery(self):
        """Practicing increases mastery level."""
        dojo = Dojo(progress_dir=str(self.tmp / "dojo"))
        dojo.learn_technique("t1", "code", "desc", "cat")
        # Practice multiple times
        for _ in range(5):
            dojo.practice_technique("t1")
        tech = dojo.get_technique("t1")
        self.assertGreater(tech.mastery_level, 0.3)
        self.assertGreater(tech.times_practiced, 1)

    def test_mastery_threshold(self):
        """Enough practice triggers mastery status."""
        dojo = Dojo(progress_dir=str(self.tmp / "dojo"))
        dojo.learn_technique("t2", "code", "desc", "cat")
        for _ in range(15):
            dojo.practice_technique("t2")
        tech = dojo.get_technique("t2")
        self.assertTrue(tech.mastered)
        self.assertGreaterEqual(tech.mastery_level, Dojo.MASTERY_THRESHOLD)

    def test_technique_shared_from_fleet(self):
        """Techniques can track fleet transfer origin."""
        dojo = Dojo(progress_dir=str(self.tmp / "dojo"))
        tech = dojo.learn_technique(
            name="pattern-x",
            code="code",
            description="Shared technique",
            shared_from="oracle1",
        )
        self.assertEqual(tech.shared_from, "oracle1")

    def test_stats_tracking(self):
        """Dojo stats are accurate."""
        dojo = Dojo(progress_dir=str(self.tmp / "dojo"))
        dojo.learn_technique("a", "c", "d", "cat1")
        dojo.learn_technique("b", "c", "d", "cat2")
        dojo.learn_technique("c", "c", "d", "cat1")
        dojo.practice_technique("a")
        dojo.master_technique("b")
        stats = dojo.get_stats()
        self.assertEqual(stats["total_techniques"], 3)
        self.assertEqual(stats["mastered"], 1)
        self.assertEqual(stats["shared_from_fleet"], 0)


if __name__ == "__main__":
    unittest.main()
