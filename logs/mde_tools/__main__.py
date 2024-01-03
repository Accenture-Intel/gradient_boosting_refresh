import sys

PACKAGE_MISSING_EXIT_CODE = 5

if sys.version_info[0] < 3:
    raise Exception("Python version not supported. Use Python3 or newer.")

try:
    from .support_tool import main
    main()
except ImportError as e:
        print("missing package: {}".format(e), file=sys.stderr)
        sys.exit(PACKAGE_MISSING_EXIT_CODE)
