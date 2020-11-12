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
    registry = defaultdict(dict)

    def encode(self, o, into=None):
        """
        Encode a Polyswarm object (``o``) into corresponding
        STIX objects, which may be selected with ``into`
        """
        source = type(o)
        if source in self.registry:
            yield from self.registry[source][into](self, o)
        elif isinstance(o, Iterable):
            for elt in o:
                yield from self.encode(elt, into=into)

    def encode_instance(self, inst):
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

    registry[ArtifactInstance][None] = encode_instance

    def encode_instance_as_file(self, inst):
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

    registry[ArtifactInstance][observables.File] = encode_instance_as_file

    def encode_instance_as_malware(self, inst):
        try:
            file = yield from emitlast(self.encode(inst, into=observables.File))
            sample_refs = [file.id]
        except StopIteration:
            sample_refs = None

        yield sdo.Malware(
            is_family=False,
            aliases=list(
                set(
                    filter(
                        None, (
                            a.metadata.get('malware_family')
                            for a in inst.assertions if a.engine_name not in {'k7', 'K7'}
                        )
                    )
                )
            ) or None,
            first_seen=inst.first_seen,
            last_seen=inst.last_seen,
            sample_refs=sample_refs,
        )

    registry[ArtifactInstance][sdo.Malware] = encode_instance_as_malware

    def encode_assertion(self, assertion):
        yield from self.encode(assertion, into=sdo.MalwareAnalysis)

    registry[Assertion][None] = encode_assertion

    def encode_assertion_as_malware_analysis(self, assertion):
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

    registry[Assertion][sdo.MalwareAnalysis] = encode_assertion_as_malware_analysis

    def encode_metadata_as_windows_pe_header(self, meta):
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

    registry[Metadata][observables.WindowsPEOptionalHeaderType] = encode_metadata_as_windows_pe_header

    def encode_metadata_as_windows_pe_binary(self, meta):
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

    registry[Metadata][observables.WindowsPEBinaryExt] = encode_metadata_as_windows_pe_binary


list(StixEncoder().encode(t1))
