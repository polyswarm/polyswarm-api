import magic

from .exiftool import ExiftoolAnalyzer


class DocAnalyzer(ExiftoolAnalyzer):
    def is_supported(self, fh):
        mimetypes = ['application/msword', 'application/vnd.ms-word.template.macroEnabled.12',
                     'application/vnd.ms-word.document.macroEnabled.12', 'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
                     'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                     'application/cdfv2']
        fh.seek(0)
        mime = magic.from_buffer(fh.read(), True).lower()

        return mime in mimetypes

    def analyze(self, fh):
        fh.seek(0)
        data = self._get_data(fh)
        fields = ['Author', 'MIMEType', 'Title', 'Pages', 'Words',
                  'Company', 'CodePage', 'AppVersion', 'RevisionNumber',
                  'Software', 'CreateDate', 'ModifyDate', 'Subject',
                  'Keywords', 'Comments']

        # hack for python 2.7
        encoder = type(u'')

        return [
            self._make_feature(*args) for args in [
                (encoder(data.get(k, '')), k.lower()) for k in fields
            ]
        ]

