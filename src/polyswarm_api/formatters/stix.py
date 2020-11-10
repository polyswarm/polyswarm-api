import datetime
from collections import defaultdict
from typing import Iterable

from stix2.v21 import sro, sdo, observables

from polyswarm_api.resources import ArtifactInstance, Metadata, Assertion


def exifdate(d):
    """
    Parse an exiftools date string

    >>> exifdate('2020:11:03 21:11:37+00:00').isoformat()
   '2020-11-03T21:11:37+00:00'
    """
    return datetime.datetime.strptime(d, '%Y:%m:%d %H:%M:%S%z')


def capedate(d):
    """Parse a CAPE Sandbox date string

    >>> capedate('2020-11-03 21:11:37').isoformat()
   '2020-11-03T21:11:37+00:00'
    """
    return datetime.datetime.strptime(d, '%Y-%m-%d %H:%M:%S')


def encode(o, into=None):
    """Convert Polyswarm objects into their STIX representation"""
    yield from StixEncoder().encode(o, into=into)


def emitlast(it):
    """Yield from an iterator, returning the final (root) STIX object yielded"""
    o = None
    for o in it:
        yield o
    return o


class StixEncoder:
    """
    >>> StixEncoder()
    """

    def __init__(self):
        self._populate_registry()

    def _populate_registry(self):
        """
        Populate the dispatch registry, used to invoke different behavior
        depending on the type of the object being encoded or type desired.
        """
        self.registry = defaultdict(dict)
        for attr in dir(self.__class__):
            fn = getattr(self, attr)
            if callable(fn) and hasattr(fn, '_registration'):
                source, into = fn._registration
                self.registry[source][into] = fn

    def encode(self, o, into=None):
        """
        Encode a Polyswarm object (``o``) into corresponding
        STIX objects, which may be selected with ``into`
        """
        source = type(o)
        if source in self.registry:
            yield from self.registry[source][into](o)
        elif isinstance(o, Iterable):
            for elt in o:
                yield from self.encode(elt, into=into)

    def register(source, into=None):
        def wrapper(fn):
            fn._registration = [source, into]
            return fn

        return wrapper

    @register(ArtifactInstance)
    def _encode_ArtifactInstance(self, inst):
        malware = yield from emitlast(self.encode(inst, into=sdo.Malware))

        for assertion in inst.assertions:
            for o in self.encode(assertion):
                yield o

                if isinstance(o, sdo.MalwareAnalysis):
                    yield sro.Relationship(
                        source_ref=o.id,
                        target_ref=malware.id,
                        relationship_type='analysis_of',
                    )

        # yield from encode(inst.metadata)

    @register(ArtifactInstance, into=observables.File)
    def _encode_ArtifactInstance_as_File(self, inst):
        if inst.type != 'FILE':
            return

        try:
            extensions = {
                'windows-pebinary-ext':
                    next(self.encode(
                        inst.metadata,
                        into=observables.WindowsPEBinaryExt,
                    ))
            }
        except (KeyError, StopIteration):
            extensions = {}

        yield observables.File(
            hashes=inst.metadata.hash,
            size=inst.size,
            name=inst.filename,
            mime_type=inst.mimetype,
            atime=exifdate(inst.metadata.exiftool['fileaccessdate']),
            ctime=exifdate(inst.metadata.exiftool['fileinodechangedate']),
            mtime=exifdate(inst.metadata.exiftool['filemodifydate']),
            extensions=extensions,
        )

    @register(ArtifactInstance, into=sdo.Malware)
    def _encode_ArtifactInstance_as_Malware(self, inst):
        try:
            file = yield from emitlast(self.encode(inst, into=observables.File))
            sample_refs = [file.id]
        except StopIteration:
            sample_refs = None

        yield sdo.Malware(
            is_family=False,
            aliases=list(set(filter(None, (
                a.metadata.get('malware_family')
                for a in inst.assertions
                if a.engine_name not in {'k7', 'K7'}
            )))) or None,
            first_seen=inst.first_seen,
            last_seen=inst.last_seen,
            sample_refs=sample_refs,
        )

    @register(Assertion)
    def _encode_Assertion(self, assertion):
        yield from self.encode(assertion, into=sdo.MalwareAnalysis)

    @register(Assertion, into=sdo.MalwareAnalysis)
    def _encode_Assertion_MalwareAnalysis(self, assertion):
        scanner = assertion.metadata.get('scanner', {})
        yield sdo.MalwareAnalysis(
            product=assertion.author_name,
            analysis_engine_version=scanner.get('vendor_version'),
            analysis_definition_version=scanner.get('signatures_version'),
            result={
                True: 'malicious',
                False: 'benign'
            }.get(assertion.verdict)
        )

    @register(Metadata, into=observables.WindowsPEOptionalHeaderType)
    def _encode_Metadata_as_WindowsPEOptionalHeaderType(self, meta):
        def version_part(nth_split, k):
            try:
                return str(meta.exiftool[k]).split('.')[nth_split]
            except KeyError:
                return None

        exif = meta.exiftool.get

        yield observables.WindowsPEOptionalHeaderType(
            size_of_code=exif('codesize'),
            size_of_initialized_data=exif('initializeddatasize'),
            address_of_entry_point=int(exif('entrypoint', '0x40010'), base=16),
            major_linker_version=version_part(0, 'linkerversion'),
            minor_linker_version=version_part(1, 'linkerversion'),
            major_subsystem_version=version_part(0, 'subsystemversion'),
            minor_subsystem_version=version_part(1, 'subsystemversion'),
            major_os_version=version_part(0, 'osversion'),
            minor_os_version=version_part(1, 'osversion'),
            major_image_version=version_part(0, 'imageversion'),
            minor_image_version=version_part(1, 'imageversion'),
        )

    @register(Metadata, into=observables.WindowsPEBinaryExt)
    def _encode_Metadata_as_WindowsPEBinaryExt(self, meta):
        try:
            optional_header = next(self.encode(meta, into=observables.WindowsPEOptionalHeaderType))
        except (StopIteration, ValueError):
            optional_header = None

        yield observables.WindowsPEBinaryExt(
            pe_type=meta.exiftool.get('filetypeextension', 'exe'),
            time_date_stamp=exifdate(meta.exiftool.get('timestamp')),
            imphash=meta.pefile.get('imphash'),
            optional_header=optional_header,
        )
