from .exiftool import ExiftoolAnalyzer


class PDFAnalyzer(ExiftoolAnalyzer):
    def is_supported(self, fh):
        fh.seek(0)
        return fh.read(5) == b'%PDF-'

    def analyze(self, fh):
        fh.seek(0)
        data = self._get_data(fh)
        fields = ['Author', 'MIMEType', 'PDFVersion', 'PageCount', 'Language',
                  'Producer', 'Creator', 'CreatorTool', 'CreateDate', 'ModifyDate']

        # hack for python 2.7
        encoder = type(u'')

        return [
            self._make_feature(*args) for args in [
                (encoder(data.get(k, '')), k.lower()) for k in fields
            ]
        ]

