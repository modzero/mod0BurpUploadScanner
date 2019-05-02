## Main feature

This module was created to roughly calculate randomness in redownloaded pictures.

It can be used to detect possible memory leaks from image renderers.
If there is some error in the image renderer logic, and it is not handling exceptions properly,
it is possible that a malformed uploaded file will trigger it, and the response will contain parts of the 
image renderer memory.
This behaviour will increase the randomness of pixels in the returned picture.

By getting the full RGB list from the response picture, and compressing it with zlib, we can
estimate the randomness of the pixels by dividing these two values with each other.

This module will give an informational issue to all redownloaded pictures, where the compression ratio is beneath the
median of all compression ratios, which can help us to see, if there is too much random noise in the picture,
and from there, we can manually investigate the incident.

## When/How it is used

Image entropy calculation is only done on the Fingerping, fuzzer, and recursive uploader module, if the "Calculate image entropy" checkbox is selected. 
The module will create informational issues where the redownloaded picture compression ratio is lower than the avarage of it. It can be used to detect issues such as this: https://blog.silentsignal.eu/2019/04/18/drop-by-drop-bleeding-through-libvips/

## Changes in the code:

Added a checkbox to the general options UI with label "Calculate image entropy". It's referenced in the code as calculate_entropy

Added new functions for the  entropy calculation/reporting. These are defined from line 866 to 922.

The calculation is called in the affected modules(Fingerping/Fuzzer/Recursive uploader), where all the ratios and request/responses are stored in a local variable called Entropy_list, which is used at the end of each module for the reporting.

Added a new helper function which calculates the median of a given list. (line 4243)
