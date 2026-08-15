# libvikingbio

This small C library contains the shared Viking Bio protocol parsing logic for the Pico bridge.

To add a new Viking Bio model later:

1. Add a new value to `vikingbio_model_t` in `include/vikingbio.h`.
2. Implement a `probe` function that detects the variant from a raw UART payload.
3. Implement a `parse` function that fills a `vikingbio_data_t` result.
4. Register the parser with `vikingbio_register_parser()` in the default registry.
5. Keep the shared data model and transport buffering outside the parser logic.

The built-in handlers currently cover the Viking Bio 20 binary packet format (`0xAA ... 0x55`) and the text fallback (`F:...,S:...,T:...`).
