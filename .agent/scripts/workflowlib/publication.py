#!/usr/bin/env python3
"""Installer-compatible publication barrier for every project CLI.

A normal CLI holds shared parent then sibling locks for its complete command.
Candidate tools inherit the installer's exact exclusive open-file descriptions;
they validate and reassert those descriptions without downgrading them.
"""
from contextlib import contextmanager
from pathlib import Path
import fcntl
import json
import os
import re
import stat
from typing import Callable, Iterator, Optional, Tuple, TypeVar

INHERITED_ENV="AGENT_WORKFLOW_INHERITED_PUBLICATION_FDS"
PUBLICATION_SUFFIX=".agent-workflow-publication.lock"
TRANSACTION_SUFFIX=".agent-workflow-transaction.json"
_CANDIDATE=re.compile(r"^\.(?P<target>[^/]+)\.agent-workflow-txn-[0-9a-f]{32}$")
_T=TypeVar("_T")
_ACTIVE_INHERITED:Optional[Tuple[Path,int,int]]=None
_ACTIVE_DEPTH=0


def publication_lock_name(project_name:str)->str:
    if not project_name or project_name in {".",".."} or "/" in project_name or "\x00" in project_name:
        raise SystemExit("project publication identity is invalid")
    return f".{project_name}{PUBLICATION_SUFFIX}"


def transaction_journal_name(project_name:str)->str:
    publication_lock_name(project_name)
    return f".{project_name}{TRANSACTION_SUFFIX}"


def _identity(value:os.stat_result)->Tuple[int,int]: return value.st_dev,value.st_ino


def _safe_parent(metadata:os.stat_result)->bool:
    return (stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==os.geteuid()
            and not stat.S_IMODE(metadata.st_mode)&0o022)


def _safe_root(metadata:os.stat_result)->bool:
    return _safe_parent(metadata)


def _safe_lock(metadata:os.stat_result)->bool:
    return (stat.S_ISREG(metadata.st_mode) and metadata.st_uid==os.geteuid()
            and metadata.st_nlink==1 and stat.S_IMODE(metadata.st_mode)==0o600)


def _open_real_directory(path:Path,label:str)->int:
    absolute=Path(os.path.abspath(str(path)))
    if __import__('platform').system()=="Darwin" and len(absolute.parts)>1 and absolute.parts[1] in {"var","tmp"}:
        alias=Path("/")/absolute.parts[1]; expected=Path("/private")/absolute.parts[1]
        try: metadata=os.lstat(alias)
        except FileNotFoundError: metadata=None
        if metadata is not None and stat.S_ISLNK(metadata.st_mode) and metadata.st_uid==0 and Path(os.path.realpath(alias))==expected:
            absolute=expected.joinpath(*absolute.parts[2:])
    flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)
    descriptor=os.open("/",flags)
    try:
        for component in absolute.parts[1:]:
            child=os.open(component,flags,dir_fd=descriptor); os.close(descriptor); descriptor=child
        result=descriptor; descriptor=-1; return result
    except OSError as error:
        raise SystemExit(f"{label} is not a safe real directory") from error
    finally:
        if descriptor>=0: os.close(descriptor)


def _validate_root(parent:int,root:Path)->None:
    flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)
    try: root_fd=os.open(root.name,flags,dir_fd=parent)
    except OSError as error: raise SystemExit("project root disappeared before publication locking") from error
    try:
        observed=os.fstat(root_fd)
        if not _safe_root(observed): raise SystemExit("project root publication authority is unsafe")
        try: expected=os.stat(root.name,dir_fd=parent,follow_symlinks=False)
        except OSError as error: raise SystemExit("project root changed during publication validation") from error
        if _identity(observed)!=_identity(expected): raise SystemExit("project root changed during publication validation")
        try: agent_fd=os.open(".agent",flags,dir_fd=root_fd)
        except OSError as error: raise SystemExit("project .agent directory is not a safe real directory") from error
        try:
            if not _safe_root(os.fstat(agent_fd)): raise SystemExit("project .agent directory is unsafe")
        finally: os.close(agent_fd)
    finally: os.close(root_fd)


def _validate_inherited(root:Path,raw:str)->Tuple[int,int]:
    try:
        value=json.loads(raw)
    except (TypeError,json.JSONDecodeError) as error:
        raise SystemExit("inherited installer publication authority is malformed") from error
    if (not isinstance(value,dict) or set(value)!={"schema","target","parent_fd","publication_fd"}
            or value.get("schema")!="agent-installer-publication-authority/v2"
            or not isinstance(value.get("target"),str)
            or type(value.get("parent_fd")) is not int or type(value.get("publication_fd")) is not int):
        raise SystemExit("inherited installer publication authority is malformed")
    target=value["target"]; parent=value["parent_fd"]; publication=value["publication_fd"]
    if parent<3 or publication<3 or parent==publication: raise SystemExit("inherited installer publication descriptors are invalid")
    candidate=_CANDIDATE.fullmatch(root.name)
    if candidate is None or candidate.group("target")!=target:
        raise SystemExit("inherited installer publication authority is outside its exact transaction candidate")
    probe=_open_real_directory(root.parent,"transaction candidate parent")
    try:
        parent_stat=os.fstat(parent); publication_stat=os.fstat(publication); probe_stat=os.fstat(probe)
        expected=os.stat(publication_lock_name(target),dir_fd=parent,follow_symlinks=False)
        if (_identity(parent_stat)!=_identity(probe_stat) or not _safe_parent(parent_stat)
                or _identity(publication_stat)!=_identity(expected) or not _safe_lock(publication_stat)):
            raise SystemExit("inherited installer publication authority is unsafe")
        _validate_root(parent,root)
        # Genuine inherited descriptors share the installer's open-file
        # descriptions, so EX|NB succeeds without blocking and does not
        # downgrade exclusive authority. Guessed/reopened descriptors fail.
        try:
            fcntl.flock(parent,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(publication,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as error:
            raise SystemExit("inherited installer publication authority is not exclusively held") from error
        os.set_inheritable(parent,False); os.set_inheritable(publication,False)
        return parent,publication
    finally: os.close(probe)


@contextmanager
def acquire_project_publication(project_root:Path)->Iterator[Tuple[int,int]]:
    global _ACTIVE_INHERITED,_ACTIVE_DEPTH
    root=Path(os.path.abspath(str(project_root)))
    if _ACTIVE_INHERITED is not None:
        active_root,parent,publication=_ACTIVE_INHERITED
        if root!=active_root: raise SystemExit("nested publication authority changed project root")
        _validate_root(parent,root); _ACTIVE_DEPTH+=1
        try: yield parent,publication
        finally: _ACTIVE_DEPTH-=1
        return
    inherited=os.environ.pop(INHERITED_ENV,None)
    if inherited is not None:
        parent,publication=_validate_inherited(root,inherited)
        _ACTIVE_INHERITED=(root,parent,publication); _ACTIVE_DEPTH=1
        try: yield parent,publication
        finally:
            _ACTIVE_DEPTH=0; _ACTIVE_INHERITED=None
            os.close(publication); os.close(parent)
        return
    parent=_open_real_directory(root.parent,"project parent publication authority")
    publication=-1
    try:
        parent_stat=os.fstat(parent)
        if not _safe_parent(parent_stat): raise SystemExit("project parent publication authority is unsafe")
        fcntl.flock(parent,fcntl.LOCK_SH)
        _validate_root(parent,root)
        name=publication_lock_name(root.name)
        flags=os.O_RDWR|os.O_CREAT|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)
        try: publication=os.open(name,flags,0o600,dir_fd=parent)
        except OSError as error: raise SystemExit("project publication lock cannot be opened safely") from error
        observed=os.fstat(publication); expected=os.stat(name,dir_fd=parent,follow_symlinks=False)
        if not _safe_lock(observed) or _identity(observed)!=_identity(expected):
            raise SystemExit("project publication lock is unsafe")
        fcntl.flock(publication,fcntl.LOCK_SH)
        expected_after=os.stat(name,dir_fd=parent,follow_symlinks=False)
        if _identity(os.fstat(publication))!=_identity(expected_after):
            raise SystemExit("project publication lock changed during acquisition")
        _validate_root(parent,root)
        journal=transaction_journal_name(root.name)
        try: os.stat(journal,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError: pass
        except OSError as error: raise SystemExit("installer recovery authority is unsafe") from error
        else: raise SystemExit("RECOVERY REQUIRED: pending installer transaction blocks project commands")
        yield parent,publication
    finally:
        if publication>=0:
            try: fcntl.flock(publication,fcntl.LOCK_UN)
            finally: os.close(publication)
        try: fcntl.flock(parent,fcntl.LOCK_UN)
        finally: os.close(parent)


def discover_project_root(argv=None)->Path:
    values=list(__import__('sys').argv[1:] if argv is None else argv)
    if '--root' in values:
        positions=[index for index,value in enumerate(values) if value=='--root']
        if len(positions)!=1 or positions[0]+1>=len(values): raise SystemExit('project --root authority is malformed')
        root=Path(values[positions[0]+1])
        if not root.is_absolute(): root=Path.cwd()/root
        return Path(os.path.abspath(str(root)))
    current=Path.cwd().resolve()
    for candidate in (current,*current.parents):
        try: metadata=os.lstat(candidate/'.agent')
        except FileNotFoundError: continue
        if stat.S_ISDIR(metadata.st_mode): return candidate
        raise SystemExit('project .agent authority is not a real directory')
    raise SystemExit('project root containing .agent was not found')


def run_cli(project_root:Path,callback:Callable[[],_T])->_T:
    with acquire_project_publication(project_root): return callback()
