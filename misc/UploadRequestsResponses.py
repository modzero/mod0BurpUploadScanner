class UploadRequestsResponses:
    """
    A class that describes requests/responses from the upload request
    to the downloaded file response again.
    """
    def __init__(self, upload_rr, preflight_rr=None, download_rr=None):
        self.upload_rr = upload_rr
        self.preflight_rr = preflight_rr
        self.download_rr = download_rr