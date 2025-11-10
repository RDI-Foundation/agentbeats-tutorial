"""
CLI tool for running cross-team evaluation.

Usage:
    python -m agentbeats.run_cross_eval config.json
"""

import argparse
import asyncio
import logging
from pathlib import Path

from agentbeats.cross_eval import CrossEvaluationConfig, CrossEvaluator


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    parser = argparse.ArgumentParser(
        description="Run cross-team security evaluation"
    )
    parser.add_argument(
        "config",
        type=Path,
        help="Path to cross-evaluation config JSON file"
    )
    parser.add_argument(
        "--generate-leaderboards-only",
        action="store_true",
        help="Skip evaluations and only generate leaderboards from existing results"
    )
    args = parser.parse_args()

    # Load configuration
    logger.info(f"Loading configuration from {args.config}")
    config = CrossEvaluationConfig.model_validate_json(args.config.read_text())

    logger.info(
        f"Configuration loaded: {len(config.green_agents)} green agents, "
        f"{len(config.purple_agents)} purple agents, "
        f"{len(config.scenarios)} scenarios"
    )

    # Create evaluator
    evaluator = CrossEvaluator(config)

    if not args.generate_leaderboards_only:
        # Run all evaluations
        logger.info("Starting cross-evaluation...")
        results = await evaluator.run_all_evaluations()
        logger.info(f"Completed {len(results)} evaluations")
    else:
        # Load existing results
        logger.info("Loading existing results...")
        results_file = config.results_dir / "raw_results.jsonl"
        if not results_file.exists():
            logger.error(f"Results file not found: {results_file}")
            return

        with open(results_file) as f:
            for line in f:
                from agentbeats.cross_eval import EvaluationRun
                result = EvaluationRun.model_validate_json(line)
                evaluator.results.append(result)

        logger.info(f"Loaded {len(evaluator.results)} results")

    # Generate leaderboards
    logger.info("Generating leaderboards...")
    public_lb, private_lb = evaluator.generate_leaderboards()

    # Display public leaderboard
    print("\n" + "=" * 80)
    print(f"PUBLIC LEADERBOARD - {public_lb.generated_at}")
    print("=" * 80)

    print("\n🔴 GREEN AGENTS (Attackers)")
    print("-" * 80)
    print(f"{'Rank':<6} {'Team':<30} {'Score':<8} {'ASR':<8} {'Coverage':<10} {'Transfer':<10}")
    print("-" * 80)

    for i, entry in enumerate(public_lb.green_leaderboard, 1):
        print(
            f"{i:<6} {entry.team_name:<30} {entry.overall_score:>6.1f}  "
            f"{entry.avg_asr:>6.1%}  {entry.avg_coverage:>8.1%}  "
            f"{entry.transferability_rate:>8.1%}"
        )

    print("\n🟣 PURPLE AGENTS (Defenders)")
    print("-" * 80)
    print(f"{'Rank':<6} {'Team':<30} {'Score':<8} {'Robust':<10} {'Fidelity':<10} {'Consist':<10}")
    print("-" * 80)

    for i, entry in enumerate(public_lb.purple_leaderboard, 1):
        print(
            f"{i:<6} {entry.team_name:<30} {entry.overall_score:>6.1f}  "
            f"{entry.avg_robustness:>8.1%}  {entry.avg_task_fidelity:>8.1%}  "
            f"{entry.consistency_rate:>8.1%}"
        )

    print("\n" + "=" * 80)
    print(f"Total Evaluations: {public_lb.total_evaluations}")
    print(f"Public leaderboard saved to: {config.results_dir / 'public_leaderboard.json'}")
    print(f"Private leaderboard saved to: {config.results_dir / 'private_leaderboard.json'}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
