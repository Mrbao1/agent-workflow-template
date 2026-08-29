#!/usr/bin/env python3
"""Byte/time-bounded subprocess execution with exact launch-scoped cleanup."""
import os
import secrets
import signal
import subprocess
import threading

MAX_OUTPUT_BYTES=1024*1024
MAX_INPUT_BYTES=16*1024*1024


def run(command,*,cwd=None,env=None,timeout=120,text=False,input=None,pass_fds=(),check=False,output_limit=MAX_OUTPUT_BYTES,**options):
    allowed={"stdout","stderr","capture_output","stdin","encoding","errors"}
    unknown=set(options)-allowed
    if unknown: raise TypeError(f"unsupported bounded process options: {sorted(unknown)}")
    try: import testrun as supervisor
    except ImportError as error: raise OSError("bounded process supervisor is unavailable") from error
    if input is None: encoded=None
    elif isinstance(input,bytes): encoded=input
    elif isinstance(input,str): encoded=input.encode(options.get("encoding") or "utf-8",errors=options.get("errors") or "strict")
    else: raise TypeError("bounded process input must be bytes, text, or None")
    if encoded is not None and len(encoded)>MAX_INPUT_BYTES: raise OSError("bounded process input exceeds its byte limit")
    token=secrets.token_hex(16); environment=dict(os.environ if env is None else env); environment[supervisor.LAUNCH_TOKEN_NAME]=token
    with supervisor.child_subreaper() as supported:
        if not supported or signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise OSError("bounded process cannot own exact child identities")
        process=subprocess.Popen(list(command),cwd=None if cwd is None else str(cwd),env=environment,
            stdin=subprocess.PIPE if encoded is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
            start_new_session=True,close_fds=True,pass_fds=tuple(pass_fds),bufsize=0)
        write_errors=[]; writer=None
        if encoded is not None:
            def write_input():
                try:
                    view=memoryview(encoded)
                    while view:
                        written=process.stdin.write(view)
                        if not isinstance(written,int) or written<=0: raise OSError("bounded process stdin write failed")
                        view=view[written:]
                except BrokenPipeError: pass
                except BaseException as error: write_errors.append(error)
                finally:
                    try: process.stdin.close()
                    except OSError: pass
            writer=threading.Thread(target=write_input,name="bounded-process-stdin",daemon=True); writer.start()
        try: observed=supervisor.supervise_bounded_process(process,timeout=timeout,launch_token=token,output_limit=output_limit,grace=5.0)
        finally:
            if writer is not None:
                writer.join(timeout=2)
                if writer.is_alive(): raise OSError("bounded process stdin writer did not terminate")
        if write_errors: raise OSError("bounded process stdin write failed") from write_errors[0]
    raw=observed["output"]
    output=raw.decode(options.get("encoding") or "utf-8",errors=options.get("errors") or "replace") if text else raw
    if observed["timed_out"]: raise subprocess.TimeoutExpired(command,timeout,output=output)
    if observed["output_limit_exceeded"]: raise OSError(f"bounded process exceeded {output_limit} output bytes")
    if observed["uncertain"] or observed["residual_descendants"] or not observed["cleanup_ok"]:
        raise OSError("bounded process cleanup identity is uncertain")
    result=subprocess.CompletedProcess(list(command),int(observed["exit_code"]),output,"" if text else b"")
    if check and result.returncode: raise subprocess.CalledProcessError(result.returncode,result.args,output=result.stdout,stderr=result.stderr)
    return result
