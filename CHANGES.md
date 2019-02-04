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
and from then, we can manually investigate the incident.


## Changes in the code:

Added a checkbox to the general options UI with label "Calculate image entropy". It's referenced in the code as calculate_entropy

Added a global variable called IMAGE_ENTROPY_CSI (line 155) to store the issues and ratios of the redownloaded pictures.

Added a new function called _calculate_image_entropy, which is defined at line 866.
This function takes a redownloaded response, and tries to get RGB list out of its body.
Then it compresses the RGB list and calculates a ratio based on the two results.

This function is called from the _make_http_request function after a redownloaded response returns with an image content type
and the calculate_entropy checkbox is checked. The call itself can be seen at line 4456.

Added a new helper function which calculates the median of a given list. (line 4182)

The reporting itself is done after all the other modules are finished their testing, but before the DoS module.
It can be seen at line 1229, where the median of the ratios are calculated, and all the pictures, which are beneath
the median are reported as an informal issue.

Please note that this code is only a Proof of Concept, the methodology, or places of the functions/calls could be changed after reconsideration. 
