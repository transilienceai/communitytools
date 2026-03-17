# Agents Index — Handala Intune Wiper Manga

## Available Agents

| Agent | File | Purpose |
|-------|------|---------|
| comic-artist | `comic-artist.md` | Generate→inspect→refine loop for all 12 manga panels |

## Usage

Agents are invoked via Claude Code's agent system. The comic-artist agent:
1. Reads all storyboard files for context
2. Iterates through panels 00-11, generating each via the `generating-panels` skill
3. Inspects each output with multimodal vision
4. Evaluates against quality criteria and regenerates if needed
5. Performs a final consistency review across all panels
