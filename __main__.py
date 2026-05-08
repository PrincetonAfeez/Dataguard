# this file makes dataguard work as python -m dataguard — it just imports cli.py and calls main()

from dataguard.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
