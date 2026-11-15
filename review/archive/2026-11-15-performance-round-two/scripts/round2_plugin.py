def pytest_configure(config):
    from experiments import patch

    patch("all")
