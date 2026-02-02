#!/usr/bin/env python3
"""
Claude Agent Benchmark Runner

This script discovers and runs benchmark tests for Claude agents,
calculating comprehensive performance metrics and saving results.
"""

import os
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
import statistics


@dataclass
class TestResult:
    """Individual test result with expected and actual outputs"""
    test_name: str
    expected: str
    actual: str
    passed: bool
    execution_time: float
    error: str = None


@dataclass
class BenchmarkMetrics:
    """Comprehensive metrics for benchmark evaluation"""
    # Confusion Matrix
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int

    # Primary Metrics
    accuracy: float
    precision: float
    recall: float
    f1_score: float

    # Additional Metrics
    specificity: float
    false_positive_rate: float
    false_negative_rate: float
    positive_predictive_value: float
    negative_predictive_value: float

    # Performance Metrics
    total_tests: int
    passed_tests: int
    failed_tests: int
    avg_execution_time: float
    total_execution_time: float

    # Test Suite Info
    test_suite: str
    timestamp: str


class BenchmarkRunner:
    """Main benchmark runner for Claude agents"""

    def __init__(self, benchmarks_dir: str = None):
        self.benchmarks_dir = Path(benchmarks_dir or os.path.dirname(__file__))
        self.claude_config = self._load_claude_config()
        self.results: List[TestResult] = []

    def _load_claude_config(self) -> Dict:
        """Load Claude configuration from .claude.json"""
        config_path = Path.home() / '.claude.json'
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load .claude.json: {e}")
            return {}

    def discover_test_suites(self) -> List[Path]:
        """Discover all test suites in the benchmarks directory"""
        test_suites = []
        for item in self.benchmarks_dir.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                # Check if directory contains test files
                test_files = list(item.glob('test_*.json')) + list(item.glob('*_test.json'))
                if test_files:
                    test_suites.append(item)
        return sorted(test_suites)

    def load_test_cases(self, test_suite_dir: Path) -> List[Dict[str, Any]]:
        """Load test cases from a test suite directory"""
        test_cases = []
        test_files = sorted(list(test_suite_dir.glob('test_*.json')) +
                          list(test_suite_dir.glob('*_test.json')))

        for test_file in test_files:
            try:
                with open(test_file, 'r') as f:
                    test_data = json.load(f)
                    if isinstance(test_data, list):
                        test_cases.extend(test_data)
                    else:
                        test_cases.append(test_data)
            except Exception as e:
                print(f"Error loading {test_file}: {e}")

        return test_cases

    def run_claude_agent(self, prompt: str, context: Dict = None) -> Tuple[str, float]:
        """
        Run Claude agent with given prompt and return output and execution time

        Args:
            prompt: The input prompt for Claude
            context: Optional context/configuration for the test

        Returns:
            Tuple of (output, execution_time)
        """
        start_time = datetime.now()

        try:
            # Prepare the command to run Claude
            cmd = ['claude', '--prompt', prompt]

            # Add any context-specific flags from test case
            if context:
                if context.get('model'):
                    cmd.extend(['--model', context['model']])
                if context.get('max_tokens'):
                    cmd.extend(['--max-tokens', str(context['max_tokens'])])

            # Run Claude agent
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            output = result.stdout.strip()
            execution_time = (datetime.now() - start_time).total_seconds()

            return output, execution_time

        except subprocess.TimeoutExpired:
            execution_time = (datetime.now() - start_time).total_seconds()
            return "ERROR: Timeout", execution_time
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            return f"ERROR: {str(e)}", execution_time

    def evaluate_output(self, expected: str, actual: str, evaluation_type: str = 'exact') -> bool:
        """
        Evaluate if the actual output matches expected output

        Args:
            expected: Expected output
            actual: Actual output from Claude
            evaluation_type: Type of evaluation ('exact', 'contains', 'semantic')

        Returns:
            Boolean indicating if test passed
        """
        if evaluation_type == 'exact':
            return expected.strip() == actual.strip()
        elif evaluation_type == 'contains':
            return expected.strip().lower() in actual.strip().lower()
        elif evaluation_type == 'semantic':
            # Simple semantic comparison - can be enhanced
            expected_words = set(expected.lower().split())
            actual_words = set(actual.lower().split())
            overlap = len(expected_words & actual_words) / len(expected_words)
            return overlap >= 0.8  # 80% word overlap threshold
        else:
            return False

    def run_test_case(self, test_case: Dict[str, Any]) -> TestResult:
        """Run a single test case and return result"""
        test_name = test_case.get('name', 'Unnamed Test')
        prompt = test_case.get('prompt', '')
        expected = test_case.get('expected', '')
        context = test_case.get('context', {})
        evaluation_type = test_case.get('evaluation_type', 'exact')

        print(f"  Running: {test_name}...", end=' ')

        actual, execution_time = self.run_claude_agent(prompt, context)
        passed = self.evaluate_output(expected, actual, evaluation_type)

        print("✓ PASS" if passed else "✗ FAIL")

        return TestResult(
            test_name=test_name,
            expected=expected,
            actual=actual,
            passed=passed,
            execution_time=execution_time,
            error=None if not actual.startswith("ERROR:") else actual
        )

    def calculate_metrics(self, results: List[TestResult]) -> BenchmarkMetrics:
        """Calculate comprehensive metrics from test results"""
        # Basic counts
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed

        # For confusion matrix, we treat:
        # - Passed tests as True Positives (TP)
        # - Failed tests where expected was positive as False Negatives (FN)
        # - Failed tests where expected was negative as False Positives (FP)
        # - Passed tests where expected was negative as True Negatives (TN)
        # This is a simplification - in practice, you'd need labeled data

        tp = passed  # Simplified: all passed tests
        fn = failed  # Simplified: all failed tests
        fp = 0  # Would need more sophisticated evaluation
        tn = 0  # Would need more sophisticated evaluation

        # Calculate metrics with zero-division handling
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        ppv = precision  # Same as precision
        npv = tn / (tn + fn) if (tn + fn) > 0 else 0

        # Performance metrics
        execution_times = [r.execution_time for r in results]
        avg_time = statistics.mean(execution_times) if execution_times else 0
        total_time = sum(execution_times)

        return BenchmarkMetrics(
            true_positives=tp,
            true_negatives=tn,
            false_positives=fp,
            false_negatives=fn,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            specificity=specificity,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            positive_predictive_value=ppv,
            negative_predictive_value=npv,
            total_tests=total,
            passed_tests=passed,
            failed_tests=failed,
            avg_execution_time=avg_time,
            total_execution_time=total_time,
            test_suite="",
            timestamp=datetime.now().isoformat()
        )

    def run_benchmark_suite(self, test_suite_dir: Path) -> BenchmarkMetrics:
        """Run all tests in a benchmark suite"""
        print(f"\n{'='*60}")
        print(f"Running Benchmark Suite: {test_suite_dir.name}")
        print(f"{'='*60}")

        test_cases = self.load_test_cases(test_suite_dir)
        print(f"Found {len(test_cases)} test cases")

        results = []
        for test_case in test_cases:
            result = self.run_test_case(test_case)
            results.append(result)

        metrics = self.calculate_metrics(results)
        metrics.test_suite = test_suite_dir.name

        return metrics

    def run_all_benchmarks(self) -> List[BenchmarkMetrics]:
        """Run all benchmark suites and return aggregated results"""
        test_suites = self.discover_test_suites()

        if not test_suites:
            print("No test suites found in benchmarks directory")
            print(f"Looking in: {self.benchmarks_dir}")
            print("\nCreate test suites by adding directories with test_*.json files")
            return []

        print(f"Discovered {len(test_suites)} test suite(s)")

        all_metrics = []
        for suite_dir in test_suites:
            metrics = self.run_benchmark_suite(suite_dir)
            all_metrics.append(metrics)
            self.print_metrics_summary(metrics)

        return all_metrics

    def print_metrics_summary(self, metrics: BenchmarkMetrics):
        """Print a summary of benchmark metrics"""
        print(f"\n{'-'*60}")
        print(f"Metrics Summary: {metrics.test_suite}")
        print(f"{'-'*60}")

        print("\n📊 Confusion Matrix:")
        print(f"  True Positives:  {metrics.true_positives:>6}")
        print(f"  True Negatives:  {metrics.true_negatives:>6}")
        print(f"  False Positives: {metrics.false_positives:>6}")
        print(f"  False Negatives: {metrics.false_negatives:>6}")

        print("\n📈 Primary Metrics:")
        print(f"  Accuracy:   {metrics.accuracy:>6.2%}")
        print(f"  Precision:  {metrics.precision:>6.2%}")
        print(f"  Recall:     {metrics.recall:>6.2%}")
        print(f"  F1 Score:   {metrics.f1_score:>6.2%}")

        print("\n📉 Additional Metrics:")
        print(f"  Specificity:              {metrics.specificity:>6.2%}")
        print(f"  False Positive Rate:      {metrics.false_positive_rate:>6.2%}")
        print(f"  False Negative Rate:      {metrics.false_negative_rate:>6.2%}")
        print(f"  Positive Predictive Value: {metrics.positive_predictive_value:>6.2%}")
        print(f"  Negative Predictive Value: {metrics.negative_predictive_value:>6.2%}")

        print("\n⏱️  Performance:")
        print(f"  Total Tests:      {metrics.total_tests:>6}")
        print(f"  Passed:           {metrics.passed_tests:>6}")
        print(f"  Failed:           {metrics.failed_tests:>6}")
        print(f"  Avg Time:         {metrics.avg_execution_time:>6.2f}s")
        print(f"  Total Time:       {metrics.total_execution_time:>6.2f}s")

    def save_results(self, metrics_list: List[BenchmarkMetrics], output_dir: Path = None):
        """Save benchmark results to a timestamped JSON file"""
        if output_dir is None:
            output_dir = self.benchmarks_dir / 'results'

        output_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        output_file = output_dir / f'benchmark_results_{timestamp}.json'

        results_data = {
            'timestamp': datetime.now().isoformat(),
            'claude_config': {
                'config_loaded': bool(self.claude_config),
                'user_id': self.claude_config.get('userID', 'unknown')
            },
            'benchmarks': [asdict(m) for m in metrics_list]
        }

        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2)

        print(f"\n{'='*60}")
        print(f"✅ Results saved to: {output_file}")
        print(f"{'='*60}\n")

        return output_file


def main():
    """Main entry point for benchmark runner"""
    print("\n" + "="*60)
    print("Claude Agent Benchmark Runner")
    print("="*60)

    # Get benchmarks directory from command line or use default
    benchmarks_dir = sys.argv[1] if len(sys.argv) > 1 else None

    runner = BenchmarkRunner(benchmarks_dir)

    # Run all benchmarks
    all_metrics = runner.run_all_benchmarks()

    # Save results
    if all_metrics:
        runner.save_results(all_metrics)

        # Print overall summary
        print("\n" + "="*60)
        print("Overall Summary")
        print("="*60)
        total_tests = sum(m.total_tests for m in all_metrics)
        total_passed = sum(m.passed_tests for m in all_metrics)
        overall_accuracy = total_passed / total_tests if total_tests > 0 else 0

        print(f"Total Test Suites: {len(all_metrics)}")
        print(f"Total Tests Run:   {total_tests}")
        print(f"Overall Accuracy:  {overall_accuracy:.2%}")
    else:
        print("\nNo benchmarks were run.")
        print("\nTo create a benchmark suite:")
        print("1. Create a directory in the benchmarks folder")
        print("2. Add test files named test_*.json or *_test.json")
        print("3. Each test file should contain test cases in JSON format")


if __name__ == '__main__':
    main()
