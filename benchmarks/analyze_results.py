#!/usr/bin/env python3
"""
Results Analyzer for Claude Agent Benchmarks

Provides visualization and analysis of benchmark results over time.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict


class ResultsAnalyzer:
    """Analyze and compare benchmark results"""

    def __init__(self, results_dir: Path = None):
        self.results_dir = results_dir or Path(__file__).parent / 'results'

    def load_results(self, filename: str = None) -> Dict:
        """Load a specific results file or the most recent one"""
        if filename:
            filepath = self.results_dir / filename
        else:
            # Get most recent results file
            result_files = sorted(self.results_dir.glob('benchmark_results_*.json'))
            if not result_files:
                print("No results files found!")
                return None
            filepath = result_files[-1]

        with open(filepath, 'r') as f:
            return json.load(f)

    def load_all_results(self) -> List[Dict]:
        """Load all results files sorted by date"""
        result_files = sorted(self.results_dir.glob('benchmark_results_*.json'))
        results = []
        for filepath in result_files:
            with open(filepath, 'r') as f:
                results.append(json.load(f))
        return results

    def print_summary(self, results: Dict = None):
        """Print a formatted summary of results"""
        if results is None:
            results = self.load_results()

        if not results:
            return

        print("\n" + "="*70)
        print(f"Benchmark Results Summary")
        print(f"Timestamp: {results['timestamp']}")
        print("="*70)

        for benchmark in results['benchmarks']:
            suite_name = benchmark['test_suite']
            print(f"\n📁 Test Suite: {suite_name}")
            print("-" * 70)

            # Key metrics in a compact table
            print(f"\n  {'Metric':<30} {'Value':>15} {'Visual':>20}")
            print(f"  {'-'*30} {'-'*15} {'-'*20}")

            metrics = [
                ('Tests Passed', f"{benchmark['passed_tests']}/{benchmark['total_tests']}",
                 self._progress_bar(benchmark['passed_tests'], benchmark['total_tests'])),
                ('Accuracy', f"{benchmark['accuracy']:.1%}",
                 self._progress_bar(benchmark['accuracy'] * 100, 100)),
                ('F1 Score', f"{benchmark['f1_score']:.1%}",
                 self._progress_bar(benchmark['f1_score'] * 100, 100)),
                ('Precision', f"{benchmark['precision']:.1%}",
                 self._progress_bar(benchmark['precision'] * 100, 100)),
                ('Recall', f"{benchmark['recall']:.1%}",
                 self._progress_bar(benchmark['recall'] * 100, 100)),
            ]

            for name, value, bar in metrics:
                print(f"  {name:<30} {value:>15} {bar:>20}")

            print(f"\n  ⏱️  Avg Time: {benchmark['avg_execution_time']:.2f}s  |  " +
                  f"Total: {benchmark['total_execution_time']:.2f}s")

    def _progress_bar(self, value: float, max_value: float, width: int = 15) -> str:
        """Generate a simple text progress bar"""
        if max_value == 0:
            return "░" * width

        filled = int((value / max_value) * width)
        bar = "█" * filled + "░" * (width - filled)
        return bar

    def compare_results(self, file1: str = None, file2: str = None):
        """Compare two benchmark results"""
        all_results = self.load_all_results()

        if len(all_results) < 2:
            print("Need at least 2 results files to compare")
            return

        results1 = all_results[-2] if file1 is None else self.load_results(file1)
        results2 = all_results[-1] if file2 is None else self.load_results(file2)

        print("\n" + "="*70)
        print("Benchmark Comparison")
        print("="*70)
        print(f"\nOlder: {results1['timestamp']}")
        print(f"Newer: {results2['timestamp']}")

        # Compare each test suite
        for b1 in results1['benchmarks']:
            suite = b1['test_suite']
            b2 = next((b for b in results2['benchmarks'] if b['test_suite'] == suite), None)

            if not b2:
                print(f"\n⚠️  Suite '{suite}' not found in newer results")
                continue

            print(f"\n📁 {suite}")
            print("-" * 70)

            comparisons = [
                ('Accuracy', b1['accuracy'], b2['accuracy']),
                ('F1 Score', b1['f1_score'], b2['f1_score']),
                ('Tests Passed', b1['passed_tests']/b1['total_tests'],
                 b2['passed_tests']/b2['total_tests']),
                ('Avg Time', b1['avg_execution_time'], b2['avg_execution_time']),
            ]

            for metric, old_val, new_val in comparisons:
                diff = new_val - old_val
                diff_pct = (diff / old_val * 100) if old_val != 0 else 0

                if metric == 'Avg Time':
                    # For time, lower is better
                    indicator = "🔽" if diff < 0 else "🔼" if diff > 0 else "➖"
                    color = "✓" if diff <= 0 else "⚠"
                else:
                    # For other metrics, higher is better
                    indicator = "🔼" if diff > 0 else "🔽" if diff < 0 else "➖"
                    color = "✓" if diff >= 0 else "⚠"

                if metric == 'Avg Time':
                    print(f"  {metric:<20} {old_val:>8.2f}s → {new_val:>8.2f}s  " +
                          f"{indicator} {abs(diff):>6.2f}s  {color}")
                else:
                    old_pct = old_val if old_val <= 1 else old_val
                    new_pct = new_val if new_val <= 1 else new_val

                    if old_val <= 1:
                        print(f"  {metric:<20} {old_pct:>8.1%} → {new_pct:>8.1%}  " +
                              f"{indicator} {abs(diff_pct):>6.1f}%  {color}")
                    else:
                        print(f"  {metric:<20} {old_val:>8.0f} → {new_val:>8.0f}  " +
                              f"{indicator}  {color}")

    def trend_analysis(self):
        """Show trends across all benchmark runs"""
        all_results = self.load_all_results()

        if len(all_results) < 2:
            print("Need at least 2 results files for trend analysis")
            return

        print("\n" + "="*70)
        print("Trend Analysis")
        print("="*70)

        # Group by test suite
        suites = {}
        for results in all_results:
            timestamp = results['timestamp']
            for benchmark in results['benchmarks']:
                suite = benchmark['test_suite']
                if suite not in suites:
                    suites[suite] = []
                suites[suite].append({
                    'timestamp': timestamp,
                    'accuracy': benchmark['accuracy'],
                    'f1_score': benchmark['f1_score'],
                    'passed': benchmark['passed_tests'],
                    'total': benchmark['total_tests']
                })

        for suite, data in suites.items():
            print(f"\n📁 {suite}")
            print("-" * 70)

            # Show trend
            accuracies = [d['accuracy'] for d in data]
            if len(accuracies) >= 2:
                trend = "📈" if accuracies[-1] > accuracies[0] else "📉" if accuracies[-1] < accuracies[0] else "➖"
                avg_accuracy = sum(accuracies) / len(accuracies)
                print(f"  Trend: {trend}  Average Accuracy: {avg_accuracy:.1%}")
                print(f"  First: {accuracies[0]:.1%}  →  Latest: {accuracies[-1]:.1%}")

            print(f"\n  {'Date':<25} {'Accuracy':>12} {'F1':>12} {'Passed':>12}")
            print(f"  {'-'*25} {'-'*12} {'-'*12} {'-'*12}")

            for d in data[-10:]:  # Show last 10 runs
                date = d['timestamp'][:19].replace('T', ' ')
                print(f"  {date:<25} {d['accuracy']:>11.1%} {d['f1_score']:>11.1%} " +
                      f"{d['passed']:>5}/{d['total']:<5}")

    def export_csv(self, output_file: str = None):
        """Export all results to CSV for further analysis"""
        all_results = self.load_all_results()

        if output_file is None:
            output_file = self.results_dir / 'benchmark_summary.csv'

        with open(output_file, 'w') as f:
            # Header
            f.write("timestamp,test_suite,accuracy,precision,recall,f1_score," +
                   "true_positives,false_negatives,total_tests,passed_tests," +
                   "avg_execution_time\n")

            # Data
            for results in all_results:
                for benchmark in results['benchmarks']:
                    f.write(f"{results['timestamp']},{benchmark['test_suite']}," +
                          f"{benchmark['accuracy']},{benchmark['precision']}," +
                          f"{benchmark['recall']},{benchmark['f1_score']}," +
                          f"{benchmark['true_positives']},{benchmark['false_negatives']}," +
                          f"{benchmark['total_tests']},{benchmark['passed_tests']}," +
                          f"{benchmark['avg_execution_time']}\n")

        print(f"\n✅ Exported to: {output_file}")


def main():
    """Main entry point"""
    analyzer = ResultsAnalyzer()

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python analyze_results.py summary              # Show latest results")
        print("  python analyze_results.py compare              # Compare last 2 runs")
        print("  python analyze_results.py trend                # Show trends over time")
        print("  python analyze_results.py export               # Export to CSV")
        return

    command = sys.argv[1].lower()

    if command == 'summary':
        analyzer.print_summary()
    elif command == 'compare':
        analyzer.compare_results()
    elif command == 'trend':
        analyzer.trend_analysis()
    elif command == 'export':
        analyzer.export_csv()
    else:
        print(f"Unknown command: {command}")


if __name__ == '__main__':
    main()
