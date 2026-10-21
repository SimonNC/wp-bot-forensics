"""Command line: python -m botforensics <command>."""

import argparse
import sys
from pathlib import Path

from botforensics.config import load_settings


def cmd_ingest(args, settings) -> int:
    from botforensics.pipeline import run, write_parquet

    result = run(Path(args.data_dir), settings)
    write_parquet(result, Path(args.out))
    s = result.stats
    print(f"lines={s.lines} parsed={s.parsed} malformed={s.malformed}")
    print(f"requests={len(result.requests)} actors={len(result.actors)} "
          f"cerber_events={len(result.events)}")
    print(result.actors["category"].value_counts().to_string())
    if not args.no_es:
        from botforensics.es import connect, index_dataframe

        es = connect(settings)
        for name, df, time_col in [
            ("weblogs-requests", result.requests, "timestamp"),
            ("weblogs-actors", result.actors, None),
            ("cerber-events", result.events, "timestamp"),
        ]:
            print(f"{name}: {index_dataframe(es, name, df, time_col)} documents")
    return 0


def cmd_make_sample(args, settings) -> int:
    from botforensics.sample import make_sample

    print(make_sample(Path(args.raw_dir), args.day, Path(args.out), settings))
    return 0


def cmd_report(args, settings) -> int:
    from botforensics.report import build_report, review_agreement

    text = build_report(Path(args.processed), Path(args.queries))
    agreement = review_agreement(Path(args.review))
    if agreement:
        text += f"\n## Validation\n\n{agreement}\n"
    Path(args.out).write_text(text, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def cmd_review(args, settings) -> int:
    from botforensics.report import write_review_sample

    try:
        n = write_review_sample(Path(args.processed), Path(args.out), force=args.force)
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{n} actors -> {args.out}")
    return 0


def cmd_esql(args, settings) -> int:
    from botforensics.es import connect

    es = connect(settings)
    for file in args.files:
        print(f"== {file}")
        resp = es.esql.query(query=Path(file).read_text(encoding="utf-8"), format="txt")
        print(resp.body if isinstance(resp.body, str) else resp)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="botforensics")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="parse, classify, write Parquet, index into ES")
    ingest.add_argument("data_dir")
    ingest.add_argument("--out", default="data/processed")
    ingest.add_argument("--no-es", action="store_true", help="skip Elasticsearch indexing")
    ingest.set_defaults(func=cmd_ingest)

    sample = sub.add_parser("make-sample", help="write a pseudonymised one-day sample")
    sample.add_argument("raw_dir")
    sample.add_argument("--day", required=True, help="YYYY-MM-DD")
    sample.add_argument("--out", default="data/sample")
    sample.set_defaults(func=cmd_make_sample)

    report = sub.add_parser("report", help="run DuckDB queries, write Markdown findings")
    report.add_argument("--processed", default="data/processed")
    report.add_argument("--queries", default="analysis/queries.sql")
    report.add_argument("--review", default="analysis/review_sample.csv")
    report.add_argument("--out", default="analysis/FINDINGS.md")
    report.set_defaults(func=cmd_report)

    review = sub.add_parser("review", help="draw 30 actors for manual validation")
    review.add_argument("--processed", default="data/processed")
    review.add_argument("--out", default="analysis/review_sample.csv")
    review.add_argument("--force", action="store_true", help="overwrite existing labels")
    review.set_defaults(func=cmd_review)

    esql = sub.add_parser("esql", help="run ES|QL query files against Elasticsearch")
    esql.add_argument("files", nargs="+")
    esql.set_defaults(func=cmd_esql)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args, load_settings())
