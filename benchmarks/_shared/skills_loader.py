"""
Load skill definitions, agent prompts, and coordination reference files into a
single system-prompt string for injection via `claude --append-system-prompt`.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple


def load_skills_content(
    skills_dir: Path,
    filter_skills: Optional[List[str]] = None,
    include_agents: bool = True,
    include_coordination_ref: bool = True,
) -> str:
    """
    Collect SKILL.md files under `skills_dir`, optional agent definitions under
    `<skills_dir>/../../agents/`, and coordination reference files under
    `<skills_dir>/coordination/reference/`.

    :param skills_dir: directory containing `<skill-name>/SKILL.md`
    :param filter_skills: if set, only include skills whose directory name is
        in this list. Falsy/None = include all.
    :param include_agents: also load `agents/*.md` if present.
    :param include_coordination_ref: also load `coordination/reference/*.md`.
    :return: concatenated system-prompt text (empty string if nothing found).
    """
    filter_tuple: Optional[Tuple[str, ...]] = (
        tuple(sorted(filter_skills)) if filter_skills else None
    )
    return _load_cached(
        skills_dir.resolve(),
        filter_tuple,
        include_agents,
        include_coordination_ref,
    )


@lru_cache(maxsize=8)
def _load_cached(
    skills_dir: Path,
    filter_tuple: Optional[Tuple[str, ...]],
    include_agents: bool,
    include_coordination_ref: bool,
) -> str:
    filter_set = set(filter_tuple) if filter_tuple else None
    sections: List[str] = []

    for skill_file in sorted(skills_dir.glob("*/SKILL.md")):
        skill_name = skill_file.parent.name
        if filter_set and skill_name not in filter_set:
            continue
        try:
            sections.append(f"## Skill: {skill_name}\n{skill_file.read_text()}")
        except Exception:
            pass

    if include_agents:
        agents_dir = skills_dir / ".." / ".." / ".." / "agents"
        if agents_dir.exists():
            for agent_file in sorted(agents_dir.glob("*.md")):
                try:
                    sections.append(f"## Agent: {agent_file.name}\n{agent_file.read_text()}")
                except Exception:
                    pass

    if include_coordination_ref:
        role_dir = skills_dir / "coordination" / "reference"
        if role_dir.exists():
            for role_file in sorted(role_dir.glob("*.md")):
                try:
                    sections.append(f"## Reference: {role_file.name}\n{role_file.read_text()}")
                except Exception:
                    pass

    if not sections:
        return ""

    return (
        "# PENTEST SKILLS & ROLE DEFINITIONS\n"
        "The following skills and role definitions are available for this security assessment.\n"
        "Use the techniques, payloads, and methodologies described below.\n\n"
        + "\n\n".join(sections)
    )
