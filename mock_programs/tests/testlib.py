import traceback


def stacktrace_on_error(wrapped):
    def run_with_stack_printer(*args, **kwargs):
        try:
            wrapped(*args, **kwargs)
        except Exception as e:
            traceback.print_exc()
            raise e

    return run_with_stack_printer
