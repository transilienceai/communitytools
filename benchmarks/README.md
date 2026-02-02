# Claude Agent Benchmarks

A comprehensive benchmarking system for evaluating Claude agents with detailed metrics including accuracy, F1 score, recall, precision, and confusion matrix analysis.

## Structure

```
benchmarks/
├── run_benchmarks.py          # Main benchmark runner script
├── README.md                  # This file
├── test_format_example.json   # Example test case format
├── results/                   # Output directory (auto-created)
│   └── benchmark_results_YYYY-MM-DD_HH-MM-SS.json
└── [test_suite_name]/        # Your test suites go here
    ├── test_feature1.json
    ├── test_feature2.json
    └── ...
```

## Quick Start

1. **Create a test suite directory:**
   ```bash
   mkdir benchmarks/my_test_suite
   ```

2. **Add test files** (see Test Format below)

3. **Run benchmarks:**
   ```bash
   python benchmarks/run_benchmarks.py
   ```

4. **View results** in `benchmarks/results/`

## Test Format

Test files should be named `test_*.json` or `*_test.json` and contain an array of test cases:

```json
[
  {
    "name": "Test Description",
    "prompt": "Your prompt for Claude",
    "expected": "Expected output",
    "evaluation_type": "exact|contains|semantic",
    "context": {
      "model": "sonnet",
      "max_tokens": 1000
    }
  }
]
```

### Evaluation Types

- **exact**: Exact string match (case-sensitive, whitespace-trimmed)
- **contains**: Expected string is contained in actual output
- **semantic**: 80%+ word overlap between expected and actual

### Optional Context Parameters

- `model`: Specify Claude model (sonnet, opus, haiku)
- `max_tokens`: Maximum tokens for response
- Additional Claude CLI flags can be added

## Metrics Calculated

### Confusion Matrix
- **True Positives (TP)**: Tests that passed correctly
- **True Negatives (TN)**: Correctly identified negative cases
- **False Positives (FP)**: Incorrectly passed tests
- **False Negatives (FN)**: Tests that should have passed but failed

### Primary Metrics
- **Accuracy**: (TP + TN) / Total
- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1 Score**: Harmonic mean of precision and recall

### Additional Metrics
- **Specificity**: True Negative Rate
- **False Positive Rate**: FP / (FP + TN)
- **False Negative Rate**: FN / (FN + TP)
- **Positive Predictive Value**: Same as Precision
- **Negative Predictive Value**: TN / (TN + FN)

### Performance Metrics
- Total tests run
- Pass/fail counts
- Average execution time
- Total execution time

## Output Format

Results are saved as JSON files with timestamps:

```json
{
  "timestamp": "2026-02-02T...",
  "claude_config": {
    "config_loaded": true,
    "user_id": "..."
  },
  "benchmarks": [
    {
      "test_suite": "my_test_suite",
      "accuracy": 0.95,
      "precision": 0.96,
      "recall": 0.94,
      "f1_score": 0.95,
      "true_positives": 19,
      "false_negatives": 1,
      "total_tests": 20,
      "passed_tests": 19,
      "failed_tests": 1,
      "avg_execution_time": 2.34,
      "total_execution_time": 46.8,
      ...
    }
  ]
}
```

## Example Test Suites

### Example 1: Code Generation Tests
```json
[
  {
    "name": "Generate Python function",
    "prompt": "Write a Python function to check if a number is prime",
    "expected": "def is_prime",
    "evaluation_type": "contains"
  }
]
```

### Example 2: Question Answering
```json
[
  {
    "name": "Basic math",
    "prompt": "What is 2 + 2?",
    "expected": "4",
    "evaluation_type": "contains"
  }
]
```

### Example 3: Code Understanding
```json
[
  {
    "name": "Explain algorithm",
    "prompt": "Explain what binary search does",
    "expected": "sorted array divide search",
    "evaluation_type": "semantic"
  }
]
```

## Configuration

The script automatically loads your Claude configuration from `~/.claude.json`, including:
- User settings
- API configuration
- Model preferences

## Advanced Usage

### Custom Benchmark Directory
```bash
python benchmarks/run_benchmarks.py /path/to/custom/benchmarks
```

### Programmatic Usage
```python
from run_benchmarks import BenchmarkRunner

runner = BenchmarkRunner('/path/to/benchmarks')
metrics = runner.run_all_benchmarks()
runner.save_results(metrics)
```

## Best Practices

1. **Organize by Feature**: Create separate test suite directories for different features
2. **Use Semantic Evaluation**: For creative/generative tasks where exact matches aren't suitable
3. **Set Timeouts**: Long-running tests have a 5-minute timeout
4. **Review Failed Tests**: Check the detailed results JSON for actual vs expected outputs
5. **Iterate**: Start with simple tests and gradually increase complexity

## Troubleshooting

### No test suites found
- Ensure directories contain `test_*.json` or `*_test.json` files
- Check that JSON files are valid

### Claude command not found
- Ensure Claude CLI is installed and in PATH
- Test with: `claude --version`

### Timeout errors
- Consider breaking complex tests into smaller units
- Adjust timeout in `run_claude_agent()` method if needed

## Contributing

To add new evaluation methods or metrics:
1. Extend the `evaluate_output()` method for new evaluation types
2. Add new metrics to `BenchmarkMetrics` dataclass
3. Update `calculate_metrics()` method accordingly

## License

This benchmark system is designed for evaluating Claude agents and follows the same license as your project.
