# Claude Agent Benchmark System - Overview

## What Is This?

A complete benchmarking infrastructure for evaluating Claude agents with:
- ✅ Automated test discovery and execution
- ✅ Comprehensive metrics (Accuracy, F1, Precision, Recall, etc.)
- ✅ Confusion matrix analysis (TP, TN, FP, FN)
- ✅ Timestamped results with full traceability
- ✅ Trend analysis and comparison tools
- ✅ CSV export for external analysis

## Quick Start

```bash
# 1. Navigate to benchmarks
cd /Users/alexander/dev/benchmarks

# 2. Create a test suite
mkdir my_tests
echo '[{"name":"Test 1","prompt":"What is 2+2?","expected":"4","evaluation_type":"contains"}]' > my_tests/test_basic.json

# 3. Run benchmarks
python run_benchmarks.py

# 4. Analyze results
python analyze_results.py summary
```

## File Structure

```
benchmarks/
├── run_benchmarks.py          # Main benchmark runner
├── analyze_results.py         # Results analysis & visualization
├── README.md                  # Detailed documentation
├── QUICKSTART.md             # Quick start guide
├── OVERVIEW.md               # This file
├── test_format_example.json  # Example test format
├── .gitignore               # Git ignore patterns
├── results/                 # Auto-generated results (gitignored)
│   └── benchmark_results_YYYY-MM-DD_HH-MM-SS.json
└── [your_test_suites]/      # Your test directories
    └── test_*.json          # Your test files
```

## Core Concepts

### 1. Test Suites
Directories containing test files. Each suite is benchmarked independently.

### 2. Test Cases
JSON files containing test definitions with:
- **name**: Test description
- **prompt**: Input for Claude
- **expected**: Expected output
- **evaluation_type**: How to compare outputs
- **context**: Optional test configuration

### 3. Evaluation Types
- **exact**: String must match exactly
- **contains**: Expected string must be in output
- **semantic**: 80%+ word overlap required

### 4. Metrics Calculated

#### Classification Metrics
- **Accuracy**: Overall correctness rate
- **Precision**: Positive predictive value
- **Recall**: Sensitivity / True positive rate
- **F1 Score**: Harmonic mean of precision & recall

#### Confusion Matrix
- **True Positives (TP)**: Correct positive predictions
- **True Negatives (TN)**: Correct negative predictions
- **False Positives (FP)**: Incorrect positive predictions
- **False Negatives (FN)**: Incorrect negative predictions

#### Performance Metrics
- Total/passed/failed test counts
- Average execution time per test
- Total execution time

## Usage Patterns

### Pattern 1: Continuous Testing
```bash
# Run after every change
while true; do
  python run_benchmarks.py
  python analyze_results.py compare
  sleep 300
done
```

### Pattern 2: Feature Development
```bash
# Create feature-specific tests
mkdir feature_auth_tests
vim feature_auth_tests/test_login.json
python run_benchmarks.py
```

### Pattern 3: Regression Testing
```bash
# Run before/after changes
python run_benchmarks.py                    # Before
# ... make changes ...
python run_benchmarks.py                    # After
python analyze_results.py compare           # Compare
```

### Pattern 4: Performance Analysis
```bash
# Export and analyze trends
python analyze_results.py trend
python analyze_results.py export
```

## Key Features

### 1. Automatic Configuration
Loads your Claude settings from `~/.claude.json` automatically.

### 2. Flexible Evaluation
Three evaluation modes support different test types:
- Exact matching for deterministic outputs
- Contains matching for partial content
- Semantic matching for natural language

### 3. Detailed Outputs
Every benchmark run creates a JSON file with:
- Full metrics breakdown
- Individual test results
- Execution timing
- Configuration snapshot

### 4. Analysis Tools
Built-in analysis script provides:
- Formatted summaries
- Side-by-side comparisons
- Trend visualization
- CSV export

## Best Practices

1. **Organize Tests Logically**
   - Group related tests into suites
   - Use descriptive directory names
   - Keep test files focused

2. **Choose Right Evaluation Type**
   - Use `exact` for deterministic outputs
   - Use `contains` for key phrases
   - Use `semantic` for natural language

3. **Iterate and Refine**
   - Start with simple tests
   - Add complexity gradually
   - Review failed tests carefully

4. **Track Over Time**
   - Keep all results files
   - Run benchmarks regularly
   - Use trend analysis

5. **Document Tests**
   - Use descriptive test names
   - Add comments in test files
   - Update README for custom suites

## Configuration from .claude.json

The system automatically reads:
- User ID and preferences
- Model configurations
- API settings
- Project-specific settings

## Extending the System

### Add New Evaluation Types
Edit `run_benchmarks.py`:
```python
def evaluate_output(self, expected, actual, evaluation_type):
    # Add your custom evaluation logic
    if evaluation_type == 'my_custom_type':
        return your_evaluation_logic()
```

### Add New Metrics
Edit `BenchmarkMetrics` dataclass:
```python
@dataclass
class BenchmarkMetrics:
    # Add new metrics
    my_custom_metric: float
```

Then update `calculate_metrics()` method.

### Custom Analysis
Use `analyze_results.py` as a starting point or load JSON directly:
```python
import json
with open('results/benchmark_results_XXX.json') as f:
    data = json.load(f)
# Perform custom analysis
```

## Output Format

Results are saved as structured JSON:

```json
{
  "timestamp": "2026-02-02T12:00:00",
  "claude_config": {
    "config_loaded": true,
    "user_id": "..."
  },
  "benchmarks": [
    {
      "test_suite": "suite_name",
      "true_positives": 18,
      "true_negatives": 0,
      "false_positives": 0,
      "false_negatives": 2,
      "accuracy": 0.9,
      "precision": 1.0,
      "recall": 0.9,
      "f1_score": 0.947,
      "total_tests": 20,
      "passed_tests": 18,
      "failed_tests": 2,
      "avg_execution_time": 2.34,
      "total_execution_time": 46.8,
      "timestamp": "2026-02-02T12:00:00"
    }
  ]
}
```

## Troubleshooting

### Issue: No test suites found
**Solution**: Ensure test files are named `test_*.json` or `*_test.json`

### Issue: Claude command not found
**Solution**: Install Claude CLI and ensure it's in PATH

### Issue: All tests timing out
**Solution**: Check Claude is running and responsive

### Issue: JSON parse errors
**Solution**: Validate JSON with `python -m json.tool your_file.json`

## Next Steps

1. Read `QUICKSTART.md` for immediate usage
2. Review `README.md` for detailed documentation
3. Check `test_format_example.json` for test format
4. Create your first test suite
5. Run benchmarks and iterate

## Contributing

This is a flexible framework designed to grow with your needs:
- Add new evaluation methods
- Extend metrics calculation
- Enhance analysis tools
- Add visualization features

## Support

- Check documentation in `README.md`
- Review examples in `test_format_example.json`
- Read script comments for implementation details
- Modify and extend as needed for your use case

---

**Ready to benchmark your Claude agents?**

```bash
python run_benchmarks.py
```
