"""STEPPER2 / SAPHash — derived from openairplay/airplay2-receiver.

This module contains the SAPHash + HandGarble code as authored by @systemcrash
in 2022 for the openairplay/airplay2-receiver project (GPLv2). The original
attribution credits the C-based "OmgHax" implementation by Foxsen et al.

THIS FILE IS A DERIVED WORK FROM GPLv2 CODE. Pyatv is MIT-licensed.

NOTHING IN PYATV IMPORTS THIS AT RUNTIME ANY MORE. The reimplementation this
note used to ask for exists: `fairplay_sap.region_a.hash_block`, recovered
from the AirParrot 3 binary by devirtualisation rather than from the GPLv2
source. `fply.m2_stepper2_compress` calls that, and
`test_fply.py::test_the_shipped_saphash_still_matches_the_vendored_gplv2_one`
proves the two agree byte-for-byte over 43 messages.

The directory is kept for exactly one reason: it is the only independent
implementation of this algorithm available to check the recovery against, so
the test above imports it directly. Deleting it would leave the recovered
code with nothing to be verified against but itself.

Whether the recovery clears a clean-room bar -- and so whether this
directory can be removed outright -- is a licensing judgement rather than a
technical one, and is left to the maintainers.

Source: https://github.com/openairplay/airplay2-receiver/blob/master/ap2/fairplay3.py
Original author: @systemcrash, 2022
"""

from ._saphash import SAPHash, modifiedMD5

__all__ = ["SAPHash", "modifiedMD5"]
