
from fingerpings.FingerpingTest import FingerpingTest
from fingerpings.FingerpingXpng import FingerpingXpng


class FingerpingTests:
    all_tests = [
        FingerpingTest("Checksums", "control", FingerpingXpng.correct_checksums, "Valid image, all libraries should be able to open it"),
        FingerpingTest("Compression", "control", FingerpingXpng.zlib_compression, "Test zlib compression level of output file"),
        FingerpingTest("filters RGB", "control", FingerpingXpng.filters_used, "Check which filters have been used in the reencoding"),
        FingerpingTest("filters indexed", "control_8bit", FingerpingXpng.filters_used, "Check which filters have been used in the reencoding"),
        FingerpingTest("control_8bit", "control_8bit", FingerpingXpng.conversion_success, "Valid paletted image"),
        FingerpingTest("control_8bit_i", "control_8bit_i", FingerpingXpng.conversion_success, "Valid paletted interlaced image"),
        FingerpingTest("control_grayscale", "control_grayscale", FingerpingXpng.conversion_success, "Valid grayscale image"),
        FingerpingTest("control_rgba", "control_rgba", FingerpingXpng.conversion_success, "Valid image with alpha"),
        FingerpingTest("CESA-2004-001", "CESA-2004-001", FingerpingXpng.conversion_success, "Invalid file triggering CESA-2004-001"),
        FingerpingTest("two_plte_chunk", "two_plte_chunk", FingerpingXpng.palette_used, "PNG file with two palettes, check which is used in result"),
        FingerpingTest("gamma_four_and_srgb", "gamma_four_and_srgb", FingerpingXpng.gamma,"PNG file with very high gamma, check if output is saturated"),
        FingerpingTest("gamma_four_nosrgb", "gamma_four_nosrgb", FingerpingXpng.gamma,"Test gamma of output image"),
        FingerpingTest("two_ihdr_chunk", "two_ihdr_chunk", FingerpingXpng.ihdr_used, "PNG image with two header chunks, check which is used"),
        FingerpingTest("idat_bad_filter", "idat_bad_filter", FingerpingXpng.bad_idat_filter, "Invalid scan line filter"),
        FingerpingTest("modified_phys", "modified_phys", FingerpingXpng.phys_chunk, "Check if decoder took phys into account"),
        FingerpingTest("truecolor_trns_chunk", "truecolor_trns_chunk", FingerpingXpng.truecolor_trns, ""),
        FingerpingTest("truecolor_alpha_trns_chunk", "truecolor_alpha_trns_chunk", FingerpingXpng.truecolor_trns, "truecolor + alpha image should not have a trns chunk"),
        FingerpingTest("transparent_bkdred", "transparent_bkdred", FingerpingXpng.truecolor_trns, ""),
        FingerpingTest("black_white", "black_white", FingerpingXpng.conversion_success, "Valid black & white image"),
        FingerpingTest("chunk_with_number_in_name_before_idat", "chunk_with_number_in_name_before_idat", FingerpingXpng.conversion_success, "Invalid chunk name"),
        FingerpingTest("CVE-2014-0333", "CVE-2014-0333", FingerpingXpng.conversion_success, ""),
        FingerpingTest("first_idat_empty", "first_idat_empty", FingerpingXpng.conversion_success, "valid file with first idat empty"),
        FingerpingTest("grayscale_with_plte", "grayscale_with_plte", FingerpingXpng.conversion_success, "Grayscale images should not have a plte chunk"),
        FingerpingTest("idat_bad_zlib_checkbits", "idat_bad_zlib_checkbits", FingerpingXpng.conversion_success, "invalid compressed data"),
        FingerpingTest("idat_bad_zlib_checksum", "idat_bad_zlib_checksum", FingerpingXpng.conversion_success, "invalid compressed data"),
        FingerpingTest("idat_bad_zlib_method", "idat_bad_zlib_method", FingerpingXpng.conversion_success, "invalid compressed data"),
        FingerpingTest("idat_empty_zlib_object", "idat_empty_zlib_object", FingerpingXpng.conversion_success, "invalid compressed data"),
        FingerpingTest("idat_junk_after_lz", "idat_junk_after_lz", FingerpingXpng.conversion_success, "Some junk appended to idat"),
        FingerpingTest("idat_too_much_data", "idat_too_much_data", FingerpingXpng.conversion_success, "too many scanlines in the compressed data"),
        FingerpingTest("idat_zlib_invalid_window", "idat_zlib_invalid_window", FingerpingXpng.conversion_success, "invalid compressed data"),
        FingerpingTest("iend_before_idat", "iend_before_idat", FingerpingXpng.conversion_success, "iend must be last chunk"),
        FingerpingTest("ihdr_height_0", "ihdr_height_0", FingerpingXpng.conversion_success, "invalid height"),
        FingerpingTest("ihdr_invalid_compression_method", "ihdr_invalid_compression_method", FingerpingXpng.conversion_success, "invalid ihdr"),
        FingerpingTest("ihdr_invalid_filter_method", "ihdr_invalid_filter_method", FingerpingXpng.conversion_success, "invalid ihdr"),
        FingerpingTest("ihdr_not_first_chunk", "ihdr_not_first_chunk", FingerpingXpng.conversion_success, "ihdr is not the first chunk"),
        FingerpingTest("ihdr_too_long", "ihdr_too_long", FingerpingXpng.conversion_success, "Invalid ihdr"),
        FingerpingTest("ihdr_too_short", "ihdr_too_short", FingerpingXpng.conversion_success, "Invalid ihdr"),
        FingerpingTest("ihdr_width_0", "ihdr_width_0", FingerpingXpng.conversion_success, "invalid width"),
        FingerpingTest("ihdr_widthheight0", "ihdr_widthheight0", FingerpingXpng.conversion_success, "invalid width and height"),
        FingerpingTest("indexed_no_plte", "indexed_no_plte", FingerpingXpng.conversion_success, "indexed png file missing the plte chunk"),
        FingerpingTest("invalid_iccp_1", "invalid_iccp_1", FingerpingXpng.conversion_success, "invalid iccp chunk"),
        FingerpingTest("invalid_iccp_2", "invalid_iccp_2", FingerpingXpng.conversion_success, "invalid iccp chunk"),
        FingerpingTest("invalid_length_iend", "invalid_length_iend", FingerpingXpng.conversion_success, "the length of the iend chunk should be zero"),
        FingerpingTest("invalid_name_ancillary_private_chunk_before_idat", "invalid_name_ancillary_private_chunk_before_idat", FingerpingXpng.conversion_success, "Invalid chunk name"),
        FingerpingTest("invalid_name_ancillary_public_chunk_before_idat_bad_checksum", "invalid_name_ancillary_public_chunk_before_idat_bad_checksum", FingerpingXpng.conversion_success, "invalid chunk name and invalid checksum"),
        FingerpingTest("invalid_name_ancillary_public_chunk_before_idat", "invalid_name_ancillary_public_chunk_before_idat", FingerpingXpng.conversion_success, "invalid chunk name"),
        FingerpingTest("invalid_name_reserved_bit_ancillary_public_chunk_before_idat", "invalid_name_reserved_bit_ancillary_public_chunk_before_idat", FingerpingXpng.conversion_success, "invalid chunk name"),
        FingerpingTest("ios_cgbl_chunk", "ios_cgbl_chunk", FingerpingXpng.conversion_success, "Apple png"),
        FingerpingTest("jng_file", "jng_file", FingerpingXpng.conversion_success, "jng file"),
        FingerpingTest("junk_after_iend", "junk_after_iend", FingerpingXpng.conversion_success, "junk at the end of the image"),
        FingerpingTest("mng_file", "mng_file", FingerpingXpng.conversion_success, "mng file"),
        FingerpingTest("no_iend", "no_iend", FingerpingXpng.conversion_success, "missing iend"),
        FingerpingTest("nonconsecutive_idat", "nonconsecutive_idat", FingerpingXpng.conversion_success, "non consecutive idat, not legal"),
        FingerpingTest("plte_after_idat", "plte_after_idat", FingerpingXpng.conversion_success, "plte after idat, it should be before"),
        FingerpingTest("png48", "png48", FingerpingXpng.conversion_success, "48bit per pixel png"),
        FingerpingTest("png64", "png64", FingerpingXpng.conversion_success, "64bit per pixel png"),
        FingerpingTest("transparent_truncated_palette", "transparent_truncated_palette", FingerpingXpng.conversion_success, "transparent color is missing in palette"),
        FingerpingTest("truncated_chunk", "truncated_chunk", FingerpingXpng.conversion_success, "truncated chunk at end of file"),
        FingerpingTest("unknown_critical_chunk_bad_checksum", "unknown_critical_chunk_bad_checksum", FingerpingXpng.conversion_success, "chunk marked as critical, but not standard with bad checksum"),
        FingerpingTest("unknown_critical_chunk", "unknown_critical_chunk", FingerpingXpng.conversion_success, "chunk marked as critical, but not standard"),

    ]
