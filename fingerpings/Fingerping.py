
from fingerping.FingerpingFingerprints import FingerpingFingerprints
from fingerping.FingerpingTests import FingerpingTests
from fingerping.FingerpingXpng import FingerpingXpng


class Fingerping:
    def __init__(self):
        self.all_tests = sorted(FingerpingTests.all_tests, key=lambda test: test.name)
        self.all_fingerprints = FingerpingFingerprints.all_fingerprints

    def do_tests(self, image_dict, warn):
        """Test all the images in a directory (don't print warnings when generating fingerprints)"""
        results = {}
        fingerprintScores = {}
        # Initialite the count of matching tests to zero for each fingerprint
        for fingerprint in self.all_fingerprints:
            fingerprintScores[fingerprint.name] = 0
        # Execute each test
        for test in self.all_tests:
            content = image_dict[test.filename]
            image = FingerpingXpng(content)
            if not image.valid == 0:
                # Only execute the test if there is an image to test
                try:
                    result = test.function(image)
                except Exception as e:
                    print("Fingerping test function threw an exception, ignoring this test for this picture. " \
                          "This might occur if the server resized the image, as this module assumes certain sizes. " \
                          "Test filename:", test.filename, "Test function:", repr(test.function)) #, "Content:"
                    # print(repr(content))
                    # print(traceback.format_exc())
                    result = 0
            else:
                result = 0
            # Save the result of the test
            results[test.name] = result

            # Check if the result matches some of the fingeprints and if so, increment the match counter
            for fingerprint in self.all_fingerprints:
                if test.name not in fingerprint.results:
                    # warn if a fingerprint(is missing the result for the test being run)
                    if warn:
                        print("warning, missing key", test.name, "in", fingerprint.name)
                elif fingerprint.results[test.name] == result:
                    fingerprintScores[fingerprint.name] += 1
        return results, fingerprintScores

    def get_results_table(self, scores):
        """Show the fingerprinting result with the most likely library match at the bottom"""
        nb = len(self.all_tests)
        text_score = sorted(scores.iteritems(), key=lambda x: x[1])
        return text_score, nb
