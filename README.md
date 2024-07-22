# stegauto
Python steganography using PNG with aes256 and automatic key detection.

> stegauto.py embed Input.PNG password Output.PNG

* Your AES key will be generated and stored in Output.bin.

> stegauto.py extract Output.PNG
>
* stegauto will search for Output.bin to apply towards Output.PNG 
