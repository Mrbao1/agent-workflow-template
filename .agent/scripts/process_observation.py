#!/usr/bin/env python3
"""Bounded kernel-native process observation for non-hostile POSIX cleanup claims."""
import ctypes
import errno
import os
import selectors
import signal as signal_module
import subprocess
import sys
import time


MAX_DARWIN_PROCESSES=131072


def bounded_trusted_command_output(command,*,environment,timeout,maximum):
    if maximum<1 or timeout<=0: raise ProcessObservationError("invalid trusted observer bounds")
    process=None; selector=None; output=bytearray(); deadline=time.monotonic()+timeout
    try:
        process=subprocess.Popen(list(command),env=dict(environment),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True,bufsize=0)
        if process.stdout is None: raise ProcessObservationError("trusted observer output pipe is unavailable")
        descriptor=process.stdout.fileno(); os.set_blocking(descriptor,False)
        selector=selectors.DefaultSelector(); selector.register(descriptor,selectors.EVENT_READ); eof=False
        while True:
            if eof and process.poll() is not None: break
            remaining=deadline-time.monotonic()
            if remaining<=0: raise ProcessObservationError("trusted observer exceeded its time limit")
            for key,_mask in selector.select(min(remaining,0.05)):
                chunk=os.read(key.fd,min(65536,max(1,maximum+1-len(output))))
                if not chunk:
                    selector.unregister(key.fd); eof=True; continue
                output.extend(chunk)
                if len(output)>maximum: raise ProcessObservationError("trusted observer exceeded its output limit")
        return process.returncode,bytes(output)
    except (OSError,subprocess.SubprocessError) as error:
        raise ProcessObservationError("trusted observer execution failed") from error
    finally:
        if process is not None and process.poll() is None:
            try: process.kill()
            except ProcessLookupError: pass
            try: process.wait(timeout=2)
            except (OSError,subprocess.SubprocessError): pass
        if selector is not None: selector.close()
        if process is not None and process.stdout is not None:
            try: process.stdout.close()
            except OSError: pass


class ProcessObservationError(RuntimeError):
    pass


class DarwinProcBSDShortInfo(ctypes.Structure):
    _fields_=[
        ("pbsi_pid",ctypes.c_uint32),("pbsi_ppid",ctypes.c_uint32),
        ("pbsi_pgid",ctypes.c_uint32),("pbsi_status",ctypes.c_uint32),
        ("pbsi_comm",ctypes.c_char*16),("pbsi_flags",ctypes.c_uint32),
        ("pbsi_uid",ctypes.c_uint32),("pbsi_gid",ctypes.c_uint32),
        ("pbsi_ruid",ctypes.c_uint32),("pbsi_rgid",ctypes.c_uint32),
        ("pbsi_svuid",ctypes.c_uint32),("pbsi_svgid",ctypes.c_uint32),
        ("pbsi_rfu",ctypes.c_uint32),
    ]


class DarwinProcBSDInfo(ctypes.Structure):
    _fields_=[
        ("pbi_flags",ctypes.c_uint32),("pbi_status",ctypes.c_uint32),
        ("pbi_xstatus",ctypes.c_uint32),("pbi_pid",ctypes.c_uint32),
        ("pbi_ppid",ctypes.c_uint32),("pbi_uid",ctypes.c_uint32),
        ("pbi_gid",ctypes.c_uint32),("pbi_ruid",ctypes.c_uint32),
        ("pbi_rgid",ctypes.c_uint32),("pbi_svuid",ctypes.c_uint32),
        ("pbi_svgid",ctypes.c_uint32),("rfu_1",ctypes.c_uint32),
        ("pbi_comm",ctypes.c_char*16),("pbi_name",ctypes.c_char*32),
        ("pbi_nfiles",ctypes.c_uint32),("pbi_pgid",ctypes.c_uint32),
        ("pbi_pjobc",ctypes.c_uint32),("e_tdev",ctypes.c_uint32),
        ("e_tpgid",ctypes.c_uint32),("pbi_nice",ctypes.c_int32),
        ("pbi_start_tvsec",ctypes.c_uint64),("pbi_start_tvusec",ctypes.c_uint64),
    ]


def _darwin_libproc():
    if sys.platform!="darwin":
        raise ProcessObservationError("Darwin kernel process observation is unavailable on this platform")
    try:
        libproc=ctypes.CDLL("/usr/lib/libproc.dylib",use_errno=True)
        listpids=libproc.proc_listpids
        listpids.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_int]
        listpids.restype=ctypes.c_int
        pidinfo=libproc.proc_pidinfo
        pidinfo.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int]
        pidinfo.restype=ctypes.c_int
    except (AttributeError,OSError) as error:
        raise ProcessObservationError("Darwin libproc process observation is unavailable") from error
    return listpids,pidinfo


def _darwin_process_info(raw_pid,pidinfo):
    info=DarwinProcBSDInfo(); ctypes.set_errno(0)
    observed=pidinfo(raw_pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
    if observed!=ctypes.sizeof(info):
        error=ctypes.get_errno()
        if error in {errno.ESRCH,errno.ENOENT}: return None
        short=DarwinProcBSDShortInfo(); ctypes.set_errno(0)
        short_observed=pidinfo(raw_pid,13,0,ctypes.byref(short),ctypes.sizeof(short)); short_error=ctypes.get_errno()
        if short_observed!=ctypes.sizeof(short):
            if short_error in {errno.ESRCH,errno.ENOENT}: return None
            raise ProcessObservationError(f"Darwin kernel UID classification is unavailable for PID {raw_pid}")
        if int(short.pbsi_pid)!=raw_pid: raise ProcessObservationError(f"Darwin kernel returned a mismatched short identity for PID {raw_pid}")
        if int(short.pbsi_uid)==os.geteuid(): raise ProcessObservationError(f"Darwin start identity is unavailable for same-user PID {raw_pid}")
        return None
    if int(info.pbi_pid)!=raw_pid: raise ProcessObservationError(f"Darwin kernel returned a mismatched process identity for PID {raw_pid}")
    if int(info.pbi_uid)!=os.geteuid(): return None
    start_sec=int(info.pbi_start_tvsec); start_usec=int(info.pbi_start_tvusec)
    if start_sec<=0 or not 0<=start_usec<=999999: raise ProcessObservationError(f"Darwin kernel start identity is invalid for PID {raw_pid}")
    name=bytes(info.pbi_name).split(b"\0",1)[0] or bytes(info.pbi_comm).split(b"\0",1)[0]
    try: session_id=os.getsid(raw_pid)
    except ProcessLookupError: return None
    except (OSError,PermissionError) as error: raise ProcessObservationError(f"Darwin session identity is unavailable for same-user PID {raw_pid}") from error
    return {"pid":raw_pid,"ppid":int(info.pbi_ppid),"pgid":int(info.pbi_pgid),"sid":session_id,
        "uid":int(info.pbi_uid),"state":"Z" if int(info.pbi_status)==5 else str(int(info.pbi_status)),
        "start_identity":f"darwin:{start_sec}:{start_usec}","command":name.decode("utf-8",errors="replace")}


def _darwin_list_snapshot(list_type,type_info,label):
    listpids,pidinfo=_darwin_libproc(); pids=(ctypes.c_int*MAX_DARWIN_PROCESSES)(); ctypes.set_errno(0)
    size=listpids(list_type,type_info,ctypes.byref(pids),ctypes.sizeof(pids))
    if size<=0 or size>=ctypes.sizeof(pids) or size%ctypes.sizeof(ctypes.c_int)!=0: raise ProcessObservationError(f"{label} is unavailable or exceeded its bound")
    result={}
    for pid in sorted(set(int(value) for value in pids[:size//ctypes.sizeof(ctypes.c_int)] if int(value)>0)):
        info=_darwin_process_info(pid,pidinfo)
        if info is not None: result[pid]=info
    return result


def darwin_process_snapshot():
    """Return an exact bounded current same-user process map."""
    return _darwin_list_snapshot(1,0,"Darwin process inventory")


def darwin_process_group_snapshot(group_id):
    """Observe one process group through libproc without numeric group signaling."""
    if not isinstance(group_id,int) or group_id<=0: raise ProcessObservationError("Darwin process group identity is invalid")
    return _darwin_list_snapshot(2,group_id,"Darwin process-group inventory")


def _linux_process_info(pid):
    path=f"/proc/{pid}/stat"; descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        raw=b""
        while len(raw)<=65536:
            chunk=os.read(descriptor,min(8192,65537-len(raw)))
            if not chunk: break
            raw+=chunk
    finally: os.close(descriptor)
    if not raw or len(raw)>65536:
        raise ProcessObservationError(f"Linux proc stat is empty or oversized for PID {pid}")
    try: text=raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ProcessObservationError(f"Linux proc stat is malformed for PID {pid}") from error
    opening=text.find("("); closing=text.rfind(")")
    if opening<=0 or closing<=opening or text[closing+1:closing+2]!=" ":
        raise ProcessObservationError(f"Linux proc stat framing is malformed for PID {pid}")
    try: observed_pid=int(text[:opening].strip())
    except ValueError as error:
        raise ProcessObservationError(f"Linux proc PID is malformed for PID {pid}") from error
    fields=text[closing+2:].split()
    if observed_pid!=pid or len(fields)<20 or len(fields[0])!=1:
        raise ProcessObservationError(f"Linux proc identity is incomplete for PID {pid}")
    try:
        parent=int(fields[1]); group=int(fields[2]); start_ticks=int(fields[19])
    except ValueError as error:
        raise ProcessObservationError(f"Linux proc identity is malformed for PID {pid}") from error
    if parent<0 or group<0 or start_ticks<0:
        raise ProcessObservationError(f"Linux proc identity is invalid for PID {pid}")
    return {"pid":pid,"ppid":parent,"pgid":group,"state":fields[0],
            "start_identity":f"linux:{start_ticks}"}


def linux_process_snapshot():
    if not sys.platform.startswith("linux"):
        raise ProcessObservationError("Linux proc process observation is unavailable on this platform")
    try:
        with os.scandir("/proc") as iterator:
            pids=[]
            for entry in iterator:
                if not entry.name.isdigit(): continue
                if len(pids)>=MAX_DARWIN_PROCESSES: raise ProcessObservationError("Linux proc process inventory exceeded its bound")
                pids.append(int(entry.name))
        pids.sort()
    except OSError as error:
        raise ProcessObservationError("Linux proc process inventory is unavailable") from error
    if not pids or len(pids)>MAX_DARWIN_PROCESSES:
        raise ProcessObservationError("Linux proc process inventory is empty or exceeded its bound")
    result={}
    for pid in pids:
        try: result[pid]=_linux_process_info(pid)
        except (FileNotFoundError,ProcessLookupError): continue
        except PermissionError:
            continue  # hidepid/other-UID entry; same-UID launch children remain readable.
    return result




def linux_process_group_snapshot(group_id):
    """Stream /proc and retain only exact members of one anchored group."""
    if not sys.platform.startswith("linux") or not isinstance(group_id,int) or group_id<=0:
        raise ProcessObservationError("Linux process group identity is invalid")
    result={}; visited=0
    try:
        with os.scandir("/proc") as iterator:
            for entry in iterator:
                if not entry.name.isdigit(): continue
                visited+=1
                if visited>1048576: raise ProcessObservationError("Linux proc traversal exceeded its bound")
                pid=int(entry.name)
                try: info=_linux_process_info(pid)
                except (FileNotFoundError,ProcessLookupError,PermissionError): continue
                if info.get("pgid")==group_id:
                    if len(result)>=4096: raise ProcessObservationError("Linux process-group inventory exceeded its bound")
                    try: info["sid"]=os.getsid(pid)
                    except ProcessLookupError: continue
                    result[pid]=info
    except OSError as error: raise ProcessObservationError("Linux proc process-group inventory is unavailable") from error
    return result


def linux_pidfd_supported():
    return (sys.platform.startswith("linux") and hasattr(os,"pidfd_open")
            and hasattr(signal_module,"pidfd_send_signal") and os.path.isdir("/proc"))


def linux_signal_identity(pid,expected_identity,signum):
    """Signal only the exact PID/starttime object through a pidfd."""
    if not linux_pidfd_supported():
        raise ProcessObservationError("Linux exact identity-bound signaling is unavailable")
    try: descriptor=os.pidfd_open(pid,0)
    except ProcessLookupError: return True
    try:
        try: observed=_linux_process_info(pid)
        except (FileNotFoundError,ProcessLookupError): return True
        if observed["start_identity"]!=expected_identity: return True
        try: signal_module.pidfd_send_signal(descriptor,signum,None,0)
        except ProcessLookupError: return True
        return True
    finally: os.close(descriptor)
