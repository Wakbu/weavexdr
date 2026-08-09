from __future__ import annotations

import os
from pathlib import Path


SERVICE_NAME = "WeaveXDR"
SERVICE_DISPLAY_NAME = "WeaveXDR Personal Security Service"


def create_service_class():
    try:
        import servicemanager
        import win32event
        import win32service
        import win32serviceutil
    except ImportError as error:
        raise RuntimeError("pywin32 is required to manage the Windows service") from error

    from xdr_graph.api import ApiRuntime, create_app
    from xdr_graph.logging_setup import configure_rotating_logging
    from xdr_graph.response import ApprovalService, DryRunResponseService
    from xdr_graph.runtime_security import RuntimeSecrets
    from xdr_graph.storage import SQLiteEventStore
    import uvicorn

    class WeaveXdrService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = "Local incident analysis, storage and authenticated WeaveXDR API"

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.server = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.server is not None:
                self.server.should_exit = True
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            data_root = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "WeaveXDR"
            logger = configure_rotating_logging(data_root / "logs")
            try:
                secrets = RuntimeSecrets.from_environment()
                store = SQLiteEventStore(data_root / "weavexdr.db")
                runtime = ApiRuntime(
                    event_store=store,
                    dry_run_service=DryRunResponseService(),
                    approval_service=ApprovalService(),
                )
                config = uvicorn.Config(
                    create_app(runtime, api_token=secrets.api_token),
                    host="127.0.0.1",
                    port=8765,
                    log_config=None,
                )
                self.server = uvicorn.Server(config)
                logger.info("service started")
                self.server.run()
            except Exception as error:
                logger.exception("service stopped unexpectedly: %s", error)
                servicemanager.LogErrorMsg(str(error))
                raise

    return WeaveXdrService, win32serviceutil


def main() -> None:
    service_class, service_util = create_service_class()
    service_util.HandleCommandLine(service_class)


if __name__ == "__main__":
    main()
