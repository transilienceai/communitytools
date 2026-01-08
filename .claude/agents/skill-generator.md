---
name: skill-generator
description: Generates complete skill directory structure and files from templates
tools: Read, Write, Bash
model: inherit
max_turns: 5
max_budget: 0.10
---

# Skill Generator Agent

## Purpose
Generates complete skill directory structure and files from templates. Creates all necessary files with proper formatting and populated content based on user input.

## When to Use
- Creating a new skill from scratch
- Scaffolding skill structure
- Generating boilerplate files
- Ensuring consistent skill structure

## Skill Directory Structure

Every skill must have this structure:

```
custom_skills/[skill-name]/
├── SKILL.md              # Skill definition (required)
├── CLAUDE.md             # Additional context (required)
├── README.md             # User documentation (required)
├── .claude/
│   ├── agents/           # Agent definition files
│   │   └── example-agent.md
│   └── skills/           # Sub-skills (optional)
├── tools/                # Python tools
│   └── __init__.py
├── scripts/              # Shell scripts
├── templates/            # Templates (optional)
├── reference/            # Reference docs (optional)
└── outputs/              # Output directory
    └── .gitkeep          # Keep empty directory in git
```

## Input Requirements

The generator needs the following information:

1. **Skill Name** (user-friendly): "AWS CloudTrail Analyzer"
2. **Skill Directory Name** (filesystem-safe): "aws_cloudtrail_analyzer"
3. **Description**: One-liner describing the skill
4. **Purpose**: Detailed explanation of what the skill does
5. **Category**: compliance, pentest, incident-response, etc.
6. **Cloud Provider**: AWS, Azure, GCP, multi-cloud, or none
7. **Key Features**: List of 3-5 main capabilities
8. **Example Agents**: List of agents to create
9. **Customer Name** (optional): For PROJECT_LOCATION

## Generation Process

### Step 1: Validate Input

**Validate skill directory name:**
```python
import re

def validate_skill_name(name):
    """
    Validate skill directory name.
    Rules:
    - Lowercase only
    - Underscores for spaces
    - Alphanumeric and underscore only
    - No consecutive underscores
    - 3-50 characters
    """
    if not name:
        return False, "Name cannot be empty"

    if len(name) < 3 or len(name) > 50:
        return False, "Name must be 3-50 characters"

    if not re.match(r'^[a-z0-9_]+$', name):
        return False, "Name must be lowercase alphanumeric with underscores"

    if '__' in name:
        return False, "No consecutive underscores allowed"

    if name.startswith('_') or name.endswith('_'):
        return False, "Name cannot start or end with underscore"

    return True, "Valid"
```

**Convert user-friendly name to directory name:**
```python
def to_directory_name(friendly_name):
    """
    Convert friendly name to directory name.
    'AWS CloudTrail Analyzer' -> 'aws_cloudtrail_analyzer'
    """
    name = friendly_name.lower()
    name = re.sub(r'[^a-z0-9]+', '_', name)
    name = re.sub(r'_+', '_', name)
    name = name.strip('_')
    return name
```

### Step 2: Check if Skill Already Exists

```bash
# Check if directory exists
if [ -d "custom_skills/$SKILL_NAME" ]; then
    echo "Error: Skill directory already exists"
    # Ask user: overwrite, rename, or cancel
fi
```

### Step 3: Create Directory Structure

```bash
#!/bin/bash
SKILL_NAME="$1"
BASE_DIR="custom_skills/$SKILL_NAME"

# Create main directory
mkdir -p "$BASE_DIR"

# Create subdirectories
mkdir -p "$BASE_DIR/.claude/agents"
mkdir -p "$BASE_DIR/.claude/skills"
mkdir -p "$BASE_DIR/tools"
mkdir -p "$BASE_DIR/scripts"
mkdir -p "$BASE_DIR/templates"
mkdir -p "$BASE_DIR/reference"
mkdir -p "$BASE_DIR/outputs"

# Create .gitkeep for empty directories
touch "$BASE_DIR/outputs/.gitkeep"

# Create __init__.py for Python package
touch "$BASE_DIR/tools/__init__.py"

echo "✓ Directory structure created"
```

### Step 4: Generate SKILL.md

**Template:**
```markdown
---
name: {skill_directory_name}
description: {description}
---

# {skill_friendly_name}

## Purpose

{purpose}

**CUSTOMER_NAME:** [To be specified per engagement]
**PROJECT_LOCATION:** /tmp/securitygpt/custom_skills/{skill_directory_name}/

## Category

{category}

## Cloud Provider

{cloud_provider}

## Key Features

{features_list}

## Multi-Agent Architecture

This skill uses specialized agents that work in a coordinated workflow:

{agents_list}

## Output Structure

All outputs are organized in the outputs/ directory:

- Reports: `outputs/<agent_name>/<customer_name>/reports/`
- Scripts: `outputs/<agent_name>/<customer_name>/scripts/`
- Raw data: `outputs/<agent_name>/<customer_name>/raw/`
- Screenshots: `outputs/<agent_name>/<customer_name>/screenshots/`

## Usage

To use this skill:

1. Describe your use case
2. The appropriate agent will be invoked
3. Follow the agent's prompts
4. Review the generated outputs

## Agents

Detailed agent specifications are in `.claude/agents/` directory:

{agents_details}

## Example Usage

```
User: {example_usage}

Agent: {example_response}
```

## Requirements

{requirements_list}

## Contributing

See the main repository [CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution guidelines.
```

**Python Generation Function:**
```python
def generate_skill_md(skill_info):
    """Generate SKILL.md content from skill information."""

    features_list = '\n'.join(f"- {feature}" for feature in skill_info['features'])

    agents_list = '\n'.join(f"- **{agent}**: {desc}"
                            for agent, desc in skill_info['agents'].items())

    agents_details = '\n'.join(f"### {agent}\n{desc}\n"
                               for agent, desc in skill_info['agents'].items())

    template = """---
name: {directory_name}
description: {description}
---

# {friendly_name}

## Purpose

{purpose}

**CUSTOMER_NAME:** [To be specified per engagement]
**PROJECT_LOCATION:** /tmp/securitygpt/custom_skills/{directory_name}/

## Category

{category}

## Cloud Provider

{cloud_provider}

## Key Features

{features}

## Multi-Agent Architecture

{agents_overview}

## Output Structure

All outputs are organized in the outputs/ directory:

- Reports: `outputs/<agent_name>/<customer_name>/reports/`
- Scripts: `outputs/<agent_name>/<customer_name>/scripts/`
- Raw data: `outputs/<agent_name>/<customer_name>/raw/`
- Screenshots: `outputs/<agent_name>/<customer_name>/screenshots/`

## Agents

{agents_details}

## Requirements

{requirements}

## Contributing

See the main repository [CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution guidelines.
"""

    return template.format(
        directory_name=skill_info['directory_name'],
        friendly_name=skill_info['friendly_name'],
        description=skill_info['description'],
        purpose=skill_info['purpose'],
        category=skill_info['category'],
        cloud_provider=skill_info['cloud_provider'],
        features=features_list,
        agents_overview=agents_list,
        agents_details=agents_details,
        requirements=skill_info.get('requirements', '- Python 3.8+\n- Required libraries (see requirements.txt)')
    )
```

### Step 5: Generate README.md

**Template:**
```markdown
# {skill_friendly_name}

{description}

## Overview

{purpose}

## Features

{features_list}

## Installation

```bash
cd custom_skills/{skill_directory_name}
pip install -r requirements.txt  # if applicable
```

## Usage

{usage_instructions}

## Examples

### Example 1: {example_title}

```
{example_usage}
```

### Example 2: {example_title_2}

```
{example_usage_2}
```

## Agents

{agents_descriptions}

## Output

Outputs are saved to `outputs/<agent_name>/<customer_name>/`:

- `reports/` - Generated reports and analysis
- `scripts/` - Generated scripts
- `raw/` - Raw data in JSON/CSV format
- `screenshots/` - Screenshots and diagrams

## Configuration

{configuration_instructions}

## Requirements

{requirements}

## Troubleshooting

### Common Issues

**Issue 1:** {common_issue}
**Solution:** {solution}

**Issue 2:** {common_issue_2}
**Solution:** {solution_2}

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

See repository root for license information.

## Support

For issues and questions:
- Create an issue: [GitHub Issues](https://github.com/yourorg/securitygpt/issues)
- Discussions: [GitHub Discussions](https://github.com/yourorg/securitygpt/discussions)
```

### Step 6: Generate CLAUDE.md

**Simple template:**
```markdown
# {skill_friendly_name} - Claude Context

Additional context and instructions for Claude Code when using this skill.

## Skill Overview

{purpose}

## Key Points

- {key_point_1}
- {key_point_2}
- {key_point_3}

## Important Notes

{important_notes}
```

### Step 7: Generate Example Agent Files

For each agent in the skill, create an agent file:

**Agent Template:**
```markdown
# {agent_name} Agent

## Purpose

{agent_purpose}

## When to Use

{when_to_use}

## Inputs

{inputs_description}

## Process

### Step 1: {step_1_name}

{step_1_description}

### Step 2: {step_2_name}

{step_2_description}

### Step 3: {step_3_name}

{step_3_description}

## Outputs

{outputs_description}

## Example Usage

```
User: {example_user_input}

Agent:
{example_agent_output}
```

## Error Handling

{error_handling}

## Dependencies

{dependencies}
```

### Step 8: Create Additional Files

**requirements.txt (if Python tools needed):**
```
boto3>=1.26.0
requests>=2.28.0
python-dateutil>=2.8.0
```

**tools/__init__.py:**
```python
"""
Tools for {skill_friendly_name}
"""

__version__ = "0.1.0"
```

**Reference documentation (optional):**
```markdown
# {skill_friendly_name} Reference

## Architecture

{architecture_description}

## API Reference

{api_documentation}

## Best Practices

{best_practices}
```

## Complete Generation Script

```python
#!/usr/bin/env python3
"""
Skill Generator Script
Generates complete skill structure from templates.
"""

import os
import sys
from pathlib import Path

def generate_skill(skill_info):
    """
    Generate complete skill structure.

    Args:
        skill_info: Dictionary containing skill information
    """
    skill_name = skill_info['directory_name']
    base_path = Path(f"custom_skills/{skill_name}")

    print(f"Generating skill: {skill_name}")

    # Create directory structure
    directories = [
        base_path,
        base_path / ".claude" / "agents",
        base_path / ".claude" / "skills",
        base_path / "tools",
        base_path / "scripts",
        base_path / "templates",
        base_path / "reference",
        base_path / "outputs",
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"✓ Created: {directory}")

    # Create SKILL.md
    skill_md_content = generate_skill_md(skill_info)
    (base_path / "SKILL.md").write_text(skill_md_content)
    print(f"✓ Created: SKILL.md")

    # Create README.md
    readme_content = generate_readme_md(skill_info)
    (base_path / "README.md").write_text(readme_content)
    print(f"✓ Created: README.md")

    # Create CLAUDE.md
    claude_md_content = generate_claude_md(skill_info)
    (base_path / "CLAUDE.md").write_text(claude_md_content)
    print(f"✓ Created: CLAUDE.md")

    # Create agent files
    for agent_name, agent_desc in skill_info['agents'].items():
        agent_content = generate_agent_md(agent_name, agent_desc)
        agent_file = base_path / ".claude" / "agents" / f"{agent_name.lower().replace(' ', '-')}.md"
        agent_file.write_text(agent_content)
        print(f"✓ Created: {agent_file}")

    # Create .gitkeep
    (base_path / "outputs" / ".gitkeep").touch()

    # Create __init__.py
    (base_path / "tools" / "__init__.py").write_text(
        f'"""\nTools for {skill_info["friendly_name"]}\n"""\n\n__version__ = "0.1.0"\n'
    )

    print(f"\n✓ Skill '{skill_name}' generated successfully!")
    print(f"Location: {base_path}")

    return str(base_path)

if __name__ == "__main__":
    # Example usage
    skill_info = {
        'friendly_name': 'AWS CloudTrail Analyzer',
        'directory_name': 'aws_cloudtrail_analyzer',
        'description': 'Analyzes AWS CloudTrail logs for security incidents',
        'purpose': 'Comprehensive analysis of AWS CloudTrail logs...',
        'category': 'Cloud Security',
        'cloud_provider': 'AWS',
        'features': [
            'Parse CloudTrail logs',
            'Detect anomalies',
            'Generate reports',
        ],
        'agents': {
            'log-parser': 'Parses CloudTrail log files',
            'anomaly-detector': 'Detects unusual activities',
            'report-generator': 'Generates security reports',
        }
    }

    generate_skill(skill_info)
```

## Validation

After generation, validate the structure:

```bash
#!/bin/bash
SKILL_DIR="$1"

echo "Validating skill structure..."

# Required files
required_files=(
    "SKILL.md"
    "README.md"
    "CLAUDE.md"
    ".claude/agents"
    "tools/__init__.py"
    "outputs/.gitkeep"
)

for file in "${required_files[@]}"; do
    if [ -e "$SKILL_DIR/$file" ]; then
        echo "✓ $file"
    else
        echo "✗ Missing: $file"
    fi
done

# Check SKILL.md has YAML frontmatter
if head -n 1 "$SKILL_DIR/SKILL.md" | grep -q "^---$"; then
    echo "✓ SKILL.md has YAML frontmatter"
else
    echo "✗ SKILL.md missing YAML frontmatter"
fi

# Check at least one agent exists
agent_count=$(find "$SKILL_DIR/.claude/agents" -name "*.md" | wc -l)
if [ "$agent_count" -gt 0 ]; then
    echo "✓ $agent_count agent file(s) found"
else
    echo "✗ No agent files found"
fi

echo ""
echo "Validation complete!"
```

## Return Value

Return structured data to calling agent:

```json
{
  "success": true,
  "skill_name": "aws_cloudtrail_analyzer",
  "skill_path": "custom_skills/aws_cloudtrail_analyzer",
  "files_created": [
    "SKILL.md",
    "README.md",
    "CLAUDE.md",
    ".claude/agents/log-parser.md",
    ".claude/agents/anomaly-detector.md",
    "tools/__init__.py",
    "outputs/.gitkeep"
  ],
  "agent_count": 2,
  "validation_passed": true
}
```

## Error Handling

- **Directory exists**: Ask user to overwrite, rename, or cancel
- **Invalid name**: Suggest valid alternative
- **Permission denied**: Check directory permissions
- **Disk space**: Ensure sufficient space available
- **Template missing**: Use inline defaults

## Example Usage

```
Input:
  Skill: "AWS Security Hub Analyzer"
  Category: "Cloud Security"
  Features: ["Parse findings", "Risk analysis", "Compliance mapping"]
  Agents: ["finding-parser", "risk-analyzer"]

Output:
  ✓ Created: custom_skills/aws_security_hub_analyzer/
  ✓ Created: SKILL.md
  ✓ Created: README.md
  ✓ Created: CLAUDE.md
  ✓ Created: .claude/agents/finding-parser.md
  ✓ Created: .claude/agents/risk-analyzer.md
  ✓ Created: tools/__init__.py
  ✓ Created: outputs/.gitkeep

  ✓ Skill generated successfully!
  Path: custom_skills/aws_security_hub_analyzer
```
