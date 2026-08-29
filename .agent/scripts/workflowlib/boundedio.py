"""Bounded, stable no-follow reads for workflow control-plane files."""
from pathlib import Path
import hashlib
import os
import platform
import stat
import secrets

DEFAULT_MAX_BYTES=16*1024*1024


def open_nofollow(path: Path,label: str):
    if not hasattr(os,"O_NOFOLLOW") or not hasattr(os,"O_DIRECTORY"):
        raise RuntimeError(f"{label} requires POSIX no-follow file support")
    if path.is_absolute() and platform.system()=="Darwin" and len(path.parts)>1 and path.parts[1] in {"var","tmp"}:
        alias=Path("/")/path.parts[1]; expected=Path("/private")/path.parts[1]
        try: alias_metadata=os.lstat(alias)
        except OSError: alias_metadata=None
        if alias_metadata is not None and stat.S_ISLNK(alias_metadata.st_mode) and alias_metadata.st_uid==0 and Path(os.path.realpath(alias))==expected:
            path=expected.joinpath(*path.parts[2:])
    if path.is_absolute():
        current=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); parts=path.parts[1:]
    else:
        current=os.open(".",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); parts=path.parts
    if not parts or any(part in {"",".",".."} for part in parts):
        os.close(current); raise RuntimeError(f"{label} path is not lexical and safe")
    try:
        for index,part in enumerate(parts):
            final=index==len(parts)-1
            following=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|(0 if final else os.O_DIRECTORY),dir_fd=current)
            os.close(current); current=following
        return current
    except BaseException:
        os.close(current); raise


def read_bytes(path,*,maximum=DEFAULT_MAX_BYTES,label="workflow file"):
    path=Path(path)
    try: observed=os.lstat(path)
    except OSError as error: raise RuntimeError(f"{label} is unreadable") from error
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1 or observed.st_size<0 or observed.st_size>maximum:
        raise RuntimeError(f"{label} is not one bounded regular file")
    try: descriptor=open_nofollow(path,label)
    except OSError as error: raise RuntimeError(f"{label} cannot be opened safely") from error
    chunks=[]; total=0
    identity=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns,item.st_mode,item.st_uid,item.st_nlink)
    try:
        opened=os.fstat(descriptor)
        if identity(opened)!=identity(observed): raise RuntimeError(f"{label} changed while opening")
        while True:
            chunk=os.read(descriptor,min(1024*1024,maximum-total+1))
            if not chunk: break
            chunks.append(chunk); total+=len(chunk)
            if total>maximum: raise RuntimeError(f"{label} exceeds its byte limit")
        after=os.fstat(descriptor)
        if identity(after)!=identity(opened) or total!=opened.st_size: raise RuntimeError(f"{label} changed while reading")
    finally: os.close(descriptor)
    return b"".join(chunks)


def read_text(path,*,maximum=DEFAULT_MAX_BYTES,label="workflow file",encoding="utf-8"):
    return read_bytes(path,maximum=maximum,label=label).decode(encoding)


def sha256(path,*,maximum=DEFAULT_MAX_BYTES,label="workflow file"):
    path=Path(path)
    try: observed=os.lstat(path)
    except OSError as error: raise RuntimeError(f"{label} is unreadable") from error
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1 or observed.st_size<0 or observed.st_size>maximum:
        raise RuntimeError(f"{label} is not one bounded regular file")
    try: descriptor=open_nofollow(path,label)
    except OSError as error: raise RuntimeError(f"{label} cannot be opened safely") from error
    identity=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns,item.st_mode,item.st_uid,item.st_nlink)
    digest=hashlib.sha256(); total=0
    try:
        opened=os.fstat(descriptor)
        if identity(opened)!=identity(observed): raise RuntimeError(f"{label} changed while opening")
        while True:
            chunk=os.read(descriptor,min(1024*1024,maximum-total+1))
            if not chunk: break
            total+=len(chunk)
            if total>maximum: raise RuntimeError(f"{label} exceeds its byte limit")
            digest.update(chunk)
        after=os.fstat(descriptor)
        if identity(after)!=identity(opened) or total!=opened.st_size: raise RuntimeError(f"{label} changed while hashing")
    finally: os.close(descriptor)
    return digest.hexdigest()


def private_directory_fd(path: Path,label: str,create: bool=True):
    path=Path(path)
    if path.is_absolute() and platform.system()=="Darwin" and len(path.parts)>1 and path.parts[1] in {"var","tmp"}:
        alias=Path("/")/path.parts[1]; expected=Path("/private")/path.parts[1]
        try: alias_metadata=os.lstat(alias)
        except OSError: alias_metadata=None
        if alias_metadata is not None and stat.S_ISLNK(alias_metadata.st_mode) and alias_metadata.st_uid==0 and Path(os.path.realpath(alias))==expected:
            path=expected.joinpath(*path.parts[2:])
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    if path.is_absolute(): current=os.open(path.anchor,flags); parts=path.parts[1:]
    else: current=os.open(".",flags); parts=path.parts
    if not parts or any(part in {"",".",".."} for part in parts): os.close(current); raise RuntimeError(f"{label} path is not lexical and safe")
    try:
        for part in parts:
            try: following=os.open(part,flags,dir_fd=current)
            except FileNotFoundError:
                if not create: raise
                try: os.mkdir(part,0o700,dir_fd=current); following=os.open(part,flags,dir_fd=current)
                except OSError as error: raise RuntimeError(f"{label} directory is unsafe") from error
            except OSError as error: raise RuntimeError(f"{label} directory is unsafe") from error
            os.close(current); current=following
        metadata=os.fstat(current)
        if metadata.st_uid!=os.geteuid() or stat.S_IMODE(metadata.st_mode)&0o022: raise RuntimeError(f"{label} directory is unsafe")
        return current
    except BaseException:
        os.close(current); raise


def atomic_write(path: Path,data: bytes,*,mode: int=0o600,label: str="workflow state"):
    path=Path(path); directory=private_directory_fd(path.parent,label,True); temporary=f".{path.name}.{secrets.token_hex(16)}"; descriptor=None
    if not path.name or path.name in {".",".."} or "/" in path.name: os.close(directory); raise RuntimeError(f"{label} filename is unsafe")
    try:
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=directory)
        view=memoryview(data); offset=0
        while offset<len(view):
            written=os.write(descriptor,view[offset:])
            if written<=0: raise OSError(f"short {label} write")
            offset+=written
        os.fsync(descriptor); os.fchmod(descriptor,mode); os.close(descriptor); descriptor=None
        os.rename(temporary,path.name,src_dir_fd=directory,dst_dir_fd=directory); temporary=""; os.fsync(directory)
    finally:
        if descriptor is not None: os.close(descriptor)
        if temporary:
            try: os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError: pass
        os.close(directory)


def create_private_file(directory_path: Path,data: bytes,*,prefix: str,suffix: str="",mode: int=0o600,label: str="workflow state"):
    directory=private_directory_fd(directory_path,label,True); name=f"{prefix}{secrets.token_hex(16)}{suffix}"; descriptor=None
    try:
        descriptor=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=directory)
        view=memoryview(data); offset=0
        while offset<len(view):
            written=os.write(descriptor,view[offset:])
            if written<=0: raise OSError(f"short {label} write")
            offset+=written
        os.fsync(descriptor); os.fchmod(descriptor,mode); os.close(descriptor); descriptor=None; os.fsync(directory)
        return Path(directory_path)/name
    finally:
        if descriptor is not None:
            os.close(descriptor)
            try: os.unlink(name,dir_fd=directory)
            except FileNotFoundError: pass
        os.close(directory)


def unlink_private(path: Path,*,missing_ok: bool=False,label: str="workflow state"):
    path=Path(path)
    try: directory=private_directory_fd(path.parent,label,False)
    except FileNotFoundError:
        if missing_ok: return
        raise
    try:
        try: os.unlink(path.name,dir_fd=directory); os.fsync(directory)
        except FileNotFoundError:
            if not missing_ok: raise
    finally: os.close(directory)


def open_private_lock(path: Path,*,label: str="workflow lock"):
    path=Path(path); directory=private_directory_fd(path.parent,label,True)
    try:
        try: descriptor=os.open(path.name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=directory)
        except OSError as error: raise RuntimeError(f"{label} is missing or unsafe") from error
        metadata=os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.geteuid() or metadata.st_nlink!=1:
            os.close(descriptor); raise RuntimeError(f"{label} is unsafe")
        os.fchmod(descriptor,0o600); metadata=os.fstat(descriptor)
        if stat.S_IMODE(metadata.st_mode)&0o077: os.close(descriptor); raise RuntimeError(f"{label} is not private")
        return os.fdopen(descriptor,"r+")
    finally: os.close(directory)


def append_private(path: Path,data: bytes,*,mode: int=0o600,label: str="workflow journal"):
    path=Path(path); directory=private_directory_fd(path.parent,label,True)
    try:
        descriptor=os.open(path.name,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,mode,dir_fd=directory)
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.geteuid() or metadata.st_nlink!=1: raise RuntimeError(f"{label} is unsafe")
            os.fchmod(descriptor,mode)
            view=memoryview(data); offset=0
            while offset<len(view):
                written=os.write(descriptor,view[offset:])
                if written<=0: raise OSError(f"short {label} write")
                offset+=written
            os.fsync(descriptor)
        finally: os.close(descriptor)
        os.fsync(directory)
    finally: os.close(directory)



def publish_immutable(path: Path,data: bytes,*,maximum: int=DEFAULT_MAX_BYTES,label: str="immutable state"):
    if len(data)>maximum: raise RuntimeError(f"{label} exceeds its byte limit")
    path=Path(path); directory=private_directory_fd(path.parent,label,True); temporary=f".{path.name}.{secrets.token_hex(16)}"; descriptor=None
    expected=hashlib.sha256(data).hexdigest()
    def existing_receipt():
        try: current=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
        except FileNotFoundError: return None
        except OSError as error: raise RuntimeError(f"{label} target is unsafe") from error
        try:
            metadata=os.fstat(current)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size>maximum: raise RuntimeError(f"{label} target is unsafe")
            hasher=hashlib.sha256(); total=0
            while True:
                chunk=os.read(current,min(1024*1024,maximum-total+1))
                if not chunk: break
                total+=len(chunk)
                if total>maximum: raise RuntimeError(f"{label} target exceeds its byte limit")
                hasher.update(chunk)
            return total,hasher.hexdigest()
        finally: os.close(current)
    try:
        observed=existing_receipt()
        if observed is not None:
            if observed!=(len(data),expected): raise RuntimeError(f"{label} digest collision")
            return
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=directory)
        view=memoryview(data); offset=0
        while offset<len(view):
            written=os.write(descriptor,view[offset:])
            if written<=0: raise OSError(f"short {label} write")
            offset+=written
        os.fsync(descriptor); os.fchmod(descriptor,0o444)
        try: os.link(temporary,path.name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
        except FileExistsError:
            if existing_receipt()!=(len(data),expected): raise RuntimeError(f"{label} digest collision")
        os.unlink(temporary,dir_fd=directory); temporary=""; os.fsync(directory)
    finally:
        if descriptor is not None: os.close(descriptor)
        if temporary:
            try: os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError: pass
        os.close(directory)
