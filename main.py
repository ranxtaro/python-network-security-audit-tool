from audit_runner import run_audit


def console_log(message):
    print(message)


if __name__ == "__main__":
    run_audit(log_callback=console_log)