# Quick Start Guide

## Setup (30 seconds)

1. Navigate to benchmarks directory:
   ```bash
   cd /Users/alexander/dev/benchmarks
   ```

2. Create your first test suite:
   ```bash
   mkdir my_first_tests
   cp test_format_example.json my_first_tests/test_basic.json
   ```

3. Run benchmarks:
   ```bash
   python run_benchmarks.py
   ```

4. View results:
   ```bash
   ls -lt results/
   cat results/benchmark_results_*.json | head -50
   ```

## What Just Happened?

The benchmark runner:
1. ✅ Discovered all test suite directories
2. ✅ Loaded test cases from JSON files
3. ✅ Ran each test through Claude agent
4. ✅ Evaluated outputs against expected results
5. ✅ Calculated comprehensive metrics
6. ✅ Saved timestamped results to `results/`

## Understanding Your Results

Your results file contains:

```json
{
  "timestamp": "When the benchmark ran",
  "claude_config": "Your Claude configuration info",
  "benchmarks": [
    {
      "test_suite": "my_first_tests",
      "accuracy": 0.95,        // 95% of tests passed
      "f1_score": 0.95,        // Balanced precision/recall
      "total_tests": 20,       // Tests executed
      "passed_tests": 19,      // Successful tests
      "avg_execution_time": 2.3 // Seconds per test
    }
  ]
}
```

## Next Steps

### 1. Create Domain-Specific Tests

```bash
# Code generation tests
mkdir code_generation_tests
echo '[{
  "name": "Generate sorting function",
  "prompt": "Write a Python function to sort a list",
  "expected": "def sort",
  "evaluation_type": "contains"
}]' > code_generation_tests/test_sort.json

# Question answering tests
mkdir qa_tests
echo '[{
  "name": "Geography question",
  "prompt": "What is the largest ocean?",
  "expected": "Pacific",
  "evaluation_type": "contains"
}]' > qa_tests/test_geography.json
```

### 2. Run and Compare

```bash
python run_benchmarks.py
```

### 3. Analyze Results

Check `results/` directory for detailed metrics including:
- Accuracy, Precision, Recall, F1 Score
- True/False Positives/Negatives
- Execution time statistics
- Per-test detailed results

## Tips

1. **Start Simple**: Begin with exact match tests, then move to semantic
2. **Iterate**: Run benchmarks frequently as you develop
3. **Track Over Time**: Keep all result files to track improvements
4. **Organize**: Use separate directories for different test categories

## Common Test Patterns

### Pattern 1: Regression Tests
Test that specific functionality hasn't broken:
```json
{
  "name": "Verify feature X still works",
  "prompt": "...",
  "expected": "...",
  "evaluation_type": "exact"
}
```

### Pattern 2: Capability Tests
Test if agent can perform task:
```json
{
  "name": "Can explain concept Y",
  "prompt": "Explain Y",
  "expected": "key terms...",
  "evaluation_type": "semantic"
}
```

### Pattern 3: Quality Tests
Test output quality:
```json
{
  "name": "Response includes required elements",
  "prompt": "...",
  "expected": "required_element",
  "evaluation_type": "contains"
}
```

## Troubleshooting

**No test suites found?**
- Make sure test files are named `test_*.json` or `*_test.json`
- Check JSON syntax with: `python -m json.tool your_test.json`

**All tests failing?**
- Verify Claude CLI works: `claude --version`
- Check test expectations are realistic
- Review actual outputs in results JSON

**Slow execution?**
- Large tests can take time
- Consider parallel execution (future feature)
- Use smaller test sets during development

## Example Workflow

```bash
# 1. Create tests for new feature
mkdir feature_xyz_tests
vim feature_xyz_tests/test_xyz.json

# 2. Run benchmarks
python run_benchmarks.py

# 3. Review results
cat results/benchmark_results_$(ls -t results/ | head -1)

# 4. Fix issues and re-run
python run_benchmarks.py

# 5. Compare results
diff results/benchmark_results_2026-02-02_10-00-00.json \
     results/benchmark_results_2026-02-02_11-00-00.json
```

## Need Help?

- See `README.md` for detailed documentation
- Check `test_format_example.json` for test format examples
- Review the script comments in `run_benchmarks.py`
