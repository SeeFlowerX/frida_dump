class CmdArgs:

    def __init__(self):
        self.attach_name = None # type: str
        self.attach_pid = None # type: str
        self.host = None # type: str
        self.runtime = None # type: str
        self.log_level = None # type: str
        self.spawn = None # type: bool
        self.shell = None # type: bool
        self.sofixer = None # type: bool
        self.TARGET = None # type: str